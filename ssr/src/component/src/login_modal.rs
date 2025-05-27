use super::{
    auth_providers::LoginProviders,
    overlay::{ShadowOverlay, ShowOverlay},
};
use candid::Principal;
use leptos::prelude::*;

#[component]
pub fn LoginModal(
    #[prop(into)] show: RwSignal<bool>,
    on_resolve: Option<Callback<Principal>>,
) -> impl IntoView {
    let lock_closing = RwSignal::new(false);
    let on_resolve = StoredValue::new(on_resolve);
    view! {
        <ShadowOverlay show=ShowOverlay::MaybeClosable {
            show,
            closable: lock_closing,
        }>
            <LoginProviders show_modal=show lock_closing on_resolve=on_resolve.get_value() />
        </ShadowOverlay>
    }
}
