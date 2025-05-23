use std::future::Future;

use auth::{
    delegate_identity, extract_identity, generate_anonymous_identity_if_required,
    set_anonymous_identity_cookie,
};
use candid::Principal;
use codee::string::FromToStringCodec;
use consts::{
    ACCOUNT_CONNECTED_STORE, REFERRER_COOKIE, USER_CANISTER_ID_STORE, USER_PRINCIPAL_STORE,
};
use ic_agent::{identity::Secp256k1Identity, Identity};
use k256::elliptic_curve::JwkEcKey;
use leptos::prelude::*;
use leptos_router::{hooks::use_query, params::Params};
use leptos_use::use_cookie;
use serde::{Deserialize, Serialize};
use yral_canisters_common::{Canisters, CanistersAuthWire};

use utils::{
    event_streaming::events::{EventCtx, EventUserDetails},
    send_wrap, MockPartialEq,
};
use yral_types::delegated_identity::DelegatedIdentityWire;

pub fn unauth_canisters() -> Canisters<false> {
    expect_context()
}

async fn do_canister_auth(
    auth: DelegatedIdentityWire,
    referrer: Option<Principal>,
) -> Result<CanistersAuthWire, ServerFnError> {
    let auth_fut = Canisters::authenticate_with_network(auth, referrer);
    let canisters = send_wrap(auth_fut).await?;
    Ok(canisters.into())
}
type AuthCansResource = Resource<Result<CanistersAuthWire, ServerFnError>>;

/// The Authenticated Canisters helper resource
/// prefer using helpers from [crate::component::canisters_prov]
/// instead
pub fn auth_state() -> AuthState {
    expect_context()
}

#[derive(Params, PartialEq, Clone)]
struct Referrer {
    user_refer: String,
}

#[derive(Copy, Clone)]
pub struct AuthState {
    temp_identity_resource: OnceResource<Option<JwkEcKey>>,
    _temp_id_cookie_resource: LocalResource<()>,
    pub referrer_store: Signal<Option<Principal>>,
    is_logged_in_with_oauth: (Signal<Option<bool>>, WriteSignal<Option<bool>>),
    new_identity_setter: RwSignal<Option<DelegatedIdentityWire>>,
    canisters_resource: AuthCansResource,
    user_canister: Memo<Option<Result<Principal, ServerFnError>>>,
    user_canister_id_cookie: Signal<Option<Principal>>,
    user_principal: Memo<Option<Result<Principal, ServerFnError>>>,
    user_principal_cookie: Signal<Option<Principal>>,
    event_ctx: EventCtx,
}

impl Default for AuthState {
    fn default() -> Self {
        let temp_identity_resource = OnceResource::new(async move {
            generate_anonymous_identity_if_required()
                .await
                .expect("Failed to generate anonymous identity?!")
        });
        let temp_id_cookie_resource = LocalResource::new(move || async move {
            let temp_identity = temp_identity_resource.await;
            let Some(id) = temp_identity else {
                return;
            };
            if let Err(e) = set_anonymous_identity_cookie(id).await {
                log::error!("Failed to set anonymous identity as cookie?! err {e}");
            }
        });

        let (referrer_cookie, set_referrer_cookie) =
            use_cookie::<Principal, FromToStringCodec>(REFERRER_COOKIE);
        let referrer_query = use_query::<Referrer>();
        let referrer_principal = Signal::derive(move || {
            let referrer = referrer_query()
                .ok()
                .and_then(|r| Principal::from_text(r.user_refer).ok());

            let referrer_cookie = referrer_cookie.get_untracked();
            if let Some(ref_princ) = referrer_cookie {
                Some(ref_princ)
            } else {
                set_referrer_cookie(referrer);
                referrer
            }
        });

        let is_logged_in_with_oauth =
            use_cookie::<bool, FromToStringCodec>(ACCOUNT_CONNECTED_STORE);

        let new_identity_setter = RwSignal::new(None::<DelegatedIdentityWire>);

        let canisters_resource: AuthCansResource = Resource::new(
            move || MockPartialEq(new_identity_setter()),
            move |auth_id| {
                send_wrap(async move {
                    let temp_identity = temp_identity_resource.await;
                    let ref_principal = referrer_principal.get_untracked();

                    if let Some(id_wire) = auth_id.0 {
                        return do_canister_auth(id_wire, ref_principal).await;
                    }

                    let Some(jwk_key) = temp_identity else {
                        let id_wire = extract_identity()
                            .await?
                            .ok_or_else(|| ServerFnError::new("No refresh cookie set?!"))?;
                        return do_canister_auth(id_wire, ref_principal).await;
                    };

                    let key = k256::SecretKey::from_jwk(&jwk_key)?;
                    let id = Secp256k1Identity::from_private_key(key);
                    let id_wire = delegate_identity(&id);

                    do_canister_auth(id_wire, ref_principal).await
                })
            },
        );

        let user_principal_store = use_cookie::<Principal, FromToStringCodec>(USER_PRINCIPAL_STORE);
        let user_principal = Memo::new(move |_| {
            let stored_principal = user_principal_store.0.get();

            let temp_id_principal = temp_identity_resource.get();
            let new_identity = new_identity_setter.get();
            let auth_cans = canisters_resource.get();

            if let Some(principal) = stored_principal {
                return Some(Ok(principal));
            }

            if let Some(id) = new_identity {
                let principal = Principal::self_authenticating(&id.from_key);
                *user_principal_store.1.write_untracked() = Some(principal);

                return Some(Ok(principal));
            }

            if let Some(Some(temp_key)) = temp_id_principal {
                let key = match k256::SecretKey::from_jwk(&temp_key) {
                    Ok(k) => k,
                    Err(e) => return Some(Err(e.into())),
                };
                let principal = Secp256k1Identity::from_private_key(key).sender().unwrap();
                *user_principal_store.1.write_untracked() = Some(principal);

                return Some(Ok(principal));
            }

            match auth_cans? {
                Ok(cans) => {
                    let principal = Principal::self_authenticating(&cans.id.from_key);
                    *user_principal_store.1.write_untracked() = Some(principal);
                    Some(Ok(principal))
                }
                Err(e) => Some(Err(e)),
            }
        });

        let user_canister_id_store =
            use_cookie::<Principal, FromToStringCodec>(USER_CANISTER_ID_STORE);
        let user_canister = Memo::new(move |_| {
            let mut stored_canister = user_canister_id_store.0.get();

            let is_new_identity = new_identity_setter.with(|id| id.is_some());
            let auth_cans = canisters_resource.get();

            if is_new_identity {
                stored_canister = None;
                *user_canister_id_store.1.write_untracked() = None;
            };

            if let Some(canister_id) = stored_canister {
                return Some(Ok(canister_id));
            }

            match auth_cans? {
                Ok(cans) => {
                    let princ = cans.user_canister;
                    *user_canister_id_store.1.write_untracked() = Some(princ);
                    Some(Ok(princ))
                }
                Err(e) => Some(Err(e)),
            }
        });

        let event_ctx = EventCtx {
            is_connected: Signal::derive(move || {
                is_logged_in_with_oauth.0.get().unwrap_or_default()
            }),
            user_details: Signal::derive(move || {
                let cans = canisters_resource.get()?.ok()?;
                Some(EventUserDetails {
                    details: cans.profile_details,
                    canister_id: cans.user_canister,
                })
            }),
        };

        Self {
            temp_identity_resource,
            _temp_id_cookie_resource: temp_id_cookie_resource,
            referrer_store: referrer_principal,
            is_logged_in_with_oauth,
            new_identity_setter,
            canisters_resource,
            user_principal,
            user_principal_cookie: user_principal_store.0,
            user_canister,
            user_canister_id_cookie: user_canister_id_store.0,
            event_ctx,
        }
    }
}

impl AuthState {
    pub fn is_logged_in_with_oauth(&self) -> Signal<bool> {
        let logged_in = self.is_logged_in_with_oauth.0;
        Signal::derive(move || logged_in.get().unwrap_or_default())
    }

    pub fn set_new_identity(
        &self,
        new_identity: DelegatedIdentityWire,
        is_logged_in_with_oauth: bool,
    ) {
        self.is_logged_in_with_oauth
            .1
            .set(Some(is_logged_in_with_oauth));

        self.new_identity_setter.set(Some(new_identity));
    }

    /// WARN: This function MUST be used with `<Suspense>`, if used inside view! {}
    /// this also tracks any changes made to user's identity, if used with <Suspend>
    pub async fn auth_cans(
        &self,
        base: Canisters<false>,
    ) -> Result<Canisters<true>, ServerFnError> {
        let cans_wire = self.canisters_resource.await?;
        let cans = Canisters::from_wire(cans_wire, base)?;
        Ok(cans)
    }

    /// WARN: This function MUST be used with `<Suspense>`, if used inside view! {}
    /// this also tracks any changes made to user's identity, if used with <Suspend>
    pub async fn cans_wire(&self) -> Result<CanistersAuthWire, ServerFnError> {
        let cans_wire = self.canisters_resource.await?;
        Ok(cans_wire)
    }

    /// WARN: The returned signal MUST be used with `<Suspense>`, unless you ABSOLUTELY know what you are doing
    pub fn user_principal_for_suspense(&self) -> Memo<Option<Result<Principal, ServerFnError>>> {
        self.user_principal
    }

    /// WARN: this must be used outside of view!{} and <Suspense>
    /// This does NOT track any changes to the user's principal
    /// use with CAUTION
    pub async fn user_principal_no_suspense(&self) -> Result<Principal, ServerFnError> {
        if let Some(principal) = self.user_principal_cookie.get_untracked() {
            return Ok(principal);
        }

        if let Some(temp_key) = self.temp_identity_resource.await {
            let key = k256::SecretKey::from_jwk(&temp_key)?;
            let principal = Secp256k1Identity::from_private_key(key).sender().unwrap();
            return Ok(principal);
        }

        let auth_cans = self.canisters_resource.await?;
        Ok(Principal::self_authenticating(&auth_cans.id.from_key))
    }

    /// WARN: The returned signal MUST be used with `<Suspense>`, unless you ABSOLUTELY know what you are doing
    pub fn user_canister_for_suspense(&self) -> Memo<Option<Result<Principal, ServerFnError>>> {
        self.user_canister
    }

    /// WARN: This must be used outside of view!{} and `<Suspense>`
    /// This does NOT track any changes to the user's canister
    /// use with CAUTION
    pub async fn user_canister_no_suspense(&self) -> Result<Principal, ServerFnError> {
        if let Some(canister) = self.user_canister_id_cookie.get_untracked() {
            return Ok(canister);
        }

        let auth_cans = self.canisters_resource.await?;
        Ok(auth_cans.user_canister)
    }

    /// Get the user principal if loaded
    /// does not have any tracking
    /// NOT RECOMMENDED TO BE USED IN DOM
    pub fn user_principal_if_available(&self) -> Option<Principal> {
        self.user_principal_cookie.get_untracked()
    }

    /// Get the user canister if loaded
    /// does not have any tracking
    /// NOT RECOMMENDED TO BE USED IN DOM
    pub fn user_canister_if_available(&self) -> Option<Principal> {
        self.user_canister_id_cookie.get_untracked()
    }

    /// WARN: Only use this for analytics
    // TODO: I really want to refactor events as a whole
    pub fn event_ctx(&self) -> EventCtx {
        self.event_ctx
    }

    /// Derive a new resource which uses the current user's canister
    /// WARN: The signals in tracker are not memoized
    pub fn derive_resource<
        S: Clone + Send + Sync + 'static,
        D: Send + Sync + Serialize + for<'x> Deserialize<'x>,
        DFut: Future<Output = Result<D, ServerFnError>> + 'static + Send,
    >(
        &self,
        tracker: impl Fn() -> S + Send + Sync + 'static,
        fetcher: impl Fn(Canisters<true>, S) -> DFut + Send + Sync + 'static + Clone,
    ) -> Resource<Result<D, ServerFnError>> {
        let cans = self.canisters_resource;
        let base = unauth_canisters();
        Resource::new(
            move || {
                // MockPartialEq is necessary
                // See: https://github.com/leptos-rs/leptos/issues/2661
                cans.track();
                MockPartialEq(tracker())
            },
            move |s| {
                let base = base.clone();
                let fetcher = fetcher.clone();
                async move {
                    let cans_wire = cans.await?;
                    let cans = Canisters::from_wire(cans_wire, base)?;
                    fetcher(cans, s.0).await
                }
            },
        )
    }

    /// WARN: Use this very carefully, this function only exists for very fine-tuned optimizations
    /// for critical pages
    /// this definitely must not be used in DOM
    pub fn auth_cans_if_available(&self) -> Option<Canisters<true>> {
        self.canisters_resource.get_untracked().and_then(|c| {
            let cans = c.ok()?;
            Canisters::from_wire(cans, unauth_canisters()).ok()
        })
    }
}
