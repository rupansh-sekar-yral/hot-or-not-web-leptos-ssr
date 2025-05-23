pub mod airdrop;
pub mod tokens;
pub mod transactions;
pub mod txn;

use candid::Principal;
use component::connect::ConnectLogin;
use component::icons::notification_icon::NotificationIcon;
use component::share_popup::ShareButtonWithFallbackPopup;
use leptos::prelude::*;
use leptos_meta::*;
use leptos_router::components::Redirect;
use leptos_router::hooks::use_params;
use leptos_router::params::Params;
use state::app_state::AppState;
use state::canisters::{auth_state, unauth_canisters};
use tokens::TokenList;
use utils::send_wrap;
use utils::try_or_redirect_opt;
use yral_canisters_common::utils::profile::ProfileDetails;

/// Controller for the login modal, passed through context
/// under wallet
#[derive(Debug, Clone, Copy)]
pub struct ShowLoginSignal(RwSignal<bool>);

#[component]
fn ProfileCard(details: ProfileDetails, is_own_account: bool, is_connected: bool) -> impl IntoView {
    let ShowLoginSignal(show_login) = expect_context();
    view! {
        <div class="w-full flex flex-col bg-neutral-900 rounded-lg p-4 gap-4">
            <div class="flex items-center gap-4">
                <img
                    src=details.profile_pic_or_random()
                    alt="Profile picture"
                    class="w-12 h-12 rounded-full object-cover shrink-0"
                />
                <span class="line-clamp-1 text-lg font-kumbh font-semibold select-all text-neutral-50">
                    // TEMP: Workaround for hydration bug until leptos 0.7
                    // class=("md:w-5/12", move || !is_connected())
                    {details.display_name_or_fallback()}
                </span>
            </div>

            <Show when=move || !is_connected && is_own_account>
                <ConnectLogin
                    show_login
                    login_text="Login to claim your Cents"
                    cta_location="wallet"
                />
            </Show>
        </div>
    }
}

#[component]
fn ProfileCardLoading() -> impl IntoView {
    view! {
        <div class="w-full flex flex-col bg-neutral-900 rounded-lg p-4 gap-4">
            <div class="flex items-center gap-4">
                <div
                    class="w-12 h-12 rounded-full bg-loading shrink-0"
                />
                <div class="flex-1 bg-loading rounded-lg h-7">
                </div>
            </div>
        </div>
    }
}

#[component]
fn Header(details: ProfileDetails, is_own_account: bool) -> impl IntoView {
    let share_link = {
        let principal = details.principal();
        format!("/wallet/{principal}")
    };
    let app_state = use_context::<AppState>();
    let message = format!(
        "Hey there 👋! Here's my wallet link on {}: {}",
        app_state.unwrap().name,
        share_link
    );

    view! {
        <div class="w-full flex items-center justify-between px-4 py-3 gap-10 ">
            <div class="text-white font-kumbh text-xl font-bold">My Wallet</div>
            <div class="flex items-center gap-8">
                <ShareButtonWithFallbackPopup share_link message />
                <Show when=move || is_own_account>
                    <a href="/wallet/notifications">
                        <NotificationIcon show_dot=false class="w-6 h-6 text-neutral-300" />
                    </a>
                </Show>
            </div>
        </div>
    }
}

#[component]
fn HeaderLoading() -> impl IntoView {
    view! {
        <div class="w-full flex items-center justify-between px-4 py-3 gap-10 ">
            <div class="text-white font-kumbh text-xl font-bold">My Wallet</div>
            <div class="flex items-center gap-8">
                <div class="w-6 h-6 rounded-full bg-loading"></div>
                <div class="w-6 h-6 rounded-full bg-loading"></div>
            </div>
        </div>
    }
}

#[component]
fn FallbackGreeter() -> impl IntoView {
    view! {
        <div class="flex flex-col">
            <span class="text-white/50 text-md">Welcome!</span>
            <div class="py-2 w-3/4 rounded-full animate-pulse bg-white/40"></div>
        </div>
        <div class="justify-self-end w-16 rounded-full animate-pulse aspect-square overflow-clip bg-white/40"></div>
    }
}

#[component]
fn BalanceFallback() -> impl IntoView {
    view! { <div class="py-3 mt-1 w-1/4 rounded-full animate-pulse bg-white/30"></div> }
}

#[derive(Params, PartialEq)]
struct WalletParams {
    id: String,
}
#[component]
pub fn Wallet() -> impl IntoView {
    let params = use_params::<WalletParams>();
    let param_principal = move || {
        params.with(|p| {
            let WalletParams { id, .. } = p.as_ref().ok()?;
            Principal::from_text(id).ok()
        })
    };

    view! {
        {move || {
            match param_principal() {
                Some(principal) => view! { <WalletImpl principal /> }.into_any(),
                None => {
                    let auth = auth_state();
                    let user_principal = auth.user_principal_for_suspense();
                    view! {
                        <Suspense>
                            {move || user_principal.get().map(|res| match res {
                                Ok(user_principal) => view! {
                                    <Redirect path=format!("/wallet/{user_principal}") />
                                },
                                Err(e) => view! {
                                    <Redirect path=format!("/error?err={e}") />
                                }
                            })}
                        </Suspense>
                    }.into_any()
                }
            }
        }}
    }
}

#[component]
pub fn WalletImpl(principal: Principal) -> impl IntoView {
    let show_login = RwSignal::new(false);

    provide_context(ShowLoginSignal(show_login));

    let cans = unauth_canisters();

    let cans2 = cans.clone();
    let canister_id = OnceResource::new(send_wrap(async move {
        let canisters = cans2;
        let user_canister = canisters
            .get_individual_canister_by_user_principal(principal)
            .await?
            .ok_or_else(|| ServerFnError::new("Failed to get user canister"))?;
        Ok::<_, ServerFnError>(user_canister)
    }));

    let profile_info_res = OnceResource::new(send_wrap(async move {
        let user_canister = canister_id.await?;
        let user = cans.individual_user(user_canister).await;
        let user_details = user.get_profile_details().await?;
        Ok::<ProfileDetails, ServerFnError>(user_details.into())
    }));

    let auth = auth_state();
    let is_connected = auth.is_logged_in_with_oauth();
    let logged_in_principal = auth.user_principal_for_suspense();
    let is_own_account = Signal::derive(move || {
        logged_in_principal
            .get()
            .map(|res| res.map(|p| p == principal))
    });

    let app_state = use_context::<AppState>();
    let page_title = app_state.unwrap().name.to_owned() + " - Wallet";
    view! {
        <div class="flex flex-col gap-4 pt-4 pb-12 bg-black min-h-dvh font-kumbh mx-auto max-w-md">
             <Title text=page_title />
             <Suspense fallback=move || view! { <HeaderLoading/> }>
                {move || {
                    let profile_details = try_or_redirect_opt!(profile_info_res.get()?);
                    let is_own_account = try_or_redirect_opt!(is_own_account.get()?);
                    Some(
                        view! {
                            <Header details=profile_details is_own_account=is_own_account/>
                        },
                    )
                }}
            </Suspense>
            <div class="flex h-full w-full flex-col items-center justify-center max-w-md mx-auto px-4 gap-4">
                <Suspense fallback=move || view! { <ProfileCardLoading/> }>
                    {move || {
                        let profile_details = try_or_redirect_opt!(profile_info_res.get()?);
                        let is_own_account = try_or_redirect_opt!(is_own_account.get()?);
                        Some(
                            view! { <ProfileCard details=profile_details is_connected=is_connected() is_own_account=is_own_account /> },
                        )
                    }}
                </Suspense>
                <Suspense>
                    {move || {
                        let canister_id = try_or_redirect_opt!(canister_id.get() ?);
                        let logged_in_user = try_or_redirect_opt!(logged_in_principal.get()?);
                        Some(
                            view! {
                                <div class="font-kumbh self-start pt-3 font-bold text-lg text-white">
                                    My tokens
                                </div>
                                <TokenList logged_in_user user_principal=principal user_canister=canister_id />
                            },
                        )
                    }}
                </Suspense>
            </div>
        </div>
    }.into_any()
}
