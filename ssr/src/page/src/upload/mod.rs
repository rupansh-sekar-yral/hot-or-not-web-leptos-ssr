mod validators;
mod video_upload;
use leptos_meta::*;

use state::canisters::auth_state;
use utils::{
    event_streaming::events::{VideoUploadInitiated, VideoUploadUploadButtonClicked},
    mixpanel::mixpanel_events::{MixPanelEvent, MixpanelGlobalProps, MixpanelVideoUploadInitProps},
    web::FileWithUrl,
};

use leptos::{
    html::{Input, Textarea},
    prelude::*,
};

use component::buttons::HighlightedButton;
use validators::{description_validator, hashtags_validator};
use video_upload::{PreVideoUpload, VideoUploader};

#[derive(Clone)]
struct UploadParams {
    file_blob: FileWithUrl,
    hashtags: Vec<String>,
    description: String,
    enable_hot_or_not: bool,
    is_nsfw: bool,
}

#[component]
fn PreUploadView(
    trigger_upload: WriteSignal<Option<UploadParams>, LocalStorage>,
    uid: RwSignal<Option<String>, LocalStorage>,
    upload_file_actual_progress: WriteSignal<f64>,
) -> impl IntoView {
    let description_err = RwSignal::new(String::new());
    let desc_err_memo = Memo::new(move |_| description_err());
    let hashtags = RwSignal::new(Vec::new());
    let hashtags_err = RwSignal::new(String::new());
    let hashtags_err_memo = Memo::new(move |_| hashtags_err());
    let file_blob = RwSignal::new_local(None::<FileWithUrl>);
    let desc = NodeRef::<Textarea>::new();
    let invalid_form = Memo::new(move |_| {
        // Description error
        !desc_err_memo.with(|desc_err_memo| desc_err_memo.is_empty())
                // Hashtags error
                || !hashtags_err_memo.with(|hashtags_err_memo| hashtags_err_memo.is_empty())
                // Hashtags are empty
                || hashtags.with(|hashtags| hashtags.is_empty())
                // Description is empty
                || desc.get().map(|d| d.value().is_empty()).unwrap_or(true)
    });
    let hashtag_inp = NodeRef::<Input>::new();
    let enable_hot_or_not = NodeRef::<Input>::new();
    let is_nsfw = NodeRef::<Input>::new();

    let auth = auth_state();
    let ev_ctx = auth.event_ctx();
    VideoUploadInitiated.send_event(ev_ctx);

    let on_submit = move || {
        VideoUploadUploadButtonClicked.send_event(ev_ctx, hashtag_inp, is_nsfw, enable_hot_or_not);

        let description = desc.get_untracked().unwrap().value();
        let hashtags = hashtags.get_untracked();
        let Some(file_blob) = file_blob.get_untracked() else {
            return;
        };
        if let Some(global) = MixpanelGlobalProps::from_ev_ctx(ev_ctx) {
            MixPanelEvent::track_video_upload_init(MixpanelVideoUploadInitProps {
                user_id: global.user_id,
                visitor_id: global.visitor_id,
                is_logged_in: global.is_logged_in,
                canister_id: global.canister_id,
                is_nsfw_enabled: global.is_nsfw_enabled,
                caption_added: !description.is_empty(),
                hashtags_added: !hashtags.is_empty(),
            });
        }
        trigger_upload.set(Some(UploadParams {
            file_blob,
            hashtags,
            description,
            enable_hot_or_not: false,
            is_nsfw: is_nsfw
                .get_untracked()
                .map(|v| v.checked())
                .unwrap_or_default(),
        }));
    };

    let hashtag_on_input = move |hts| match hashtags_validator(hts) {
        Ok(hts) => {
            hashtags.set(hts);
            hashtags_err.set(String::new());
        }
        Err(e) => hashtags_err.set(e),
    };

    Effect::new(move |_| {
        let Some(hashtag_inp) = hashtag_inp.get() else {
            return;
        };

        let val = hashtag_inp.value();
        if !val.is_empty() {
            hashtag_on_input(val);
        }
    });

    view! {
        <div class="flex flex-col gap-4 justify-center items-center p-0 mx-auto w-full min-h-screen bg-transparent lg:flex-row lg:gap-20">
            <div class="flex flex-col justify-center items-center px-2 mx-4 mt-4 mb-4 text-center rounded-2xl sm:px-4 sm:mx-6 sm:w-full sm:h-auto lg:overflow-y-auto lg:px-0 lg:mx-0 w-[358px] h-[300px] sm:min-h-[380px] sm:max-h-[70vh] lg:w-[627px] lg:h-[600px]">
                <PreVideoUpload
                    file_blob=file_blob
                    uid=uid
                    upload_file_actual_progress=upload_file_actual_progress
                />
            </div>
            <div class="flex overflow-y-auto flex-col gap-4 justify-between p-2 w-full h-auto rounded-2xl max-w-[627px] min-h-[400px] max-h-[90vh] lg:w-[627px] lg:h-[600px]">
                <h2 class="mb-2 font-light text-white text-[32px]">Upload Video</h2>
                <div class="flex flex-col gap-y-1">
                    <label for="caption-input" class="mb-1 font-light text-[20px] text-neutral-300">
                        Caption
                    </label>
                    <Show when=move || {
                        description_err.with(|description_err| !description_err.is_empty())
                    }>
                        <span class="text-sm text-red-500">{desc_err_memo()}</span>
                    </Show>
                    <textarea
                        id="caption-input"
                        node_ref=desc
                        on:input=move |ev| {
                            let desc = event_target_value(&ev);
                            description_err
                                .set(description_validator(desc).err().unwrap_or_default());
                        }
                        class="p-3 min-w-full rounded-lg border transition outline-none focus:border-pink-400 focus:ring-pink-400 bg-neutral-900 border-neutral-800 text-[15px] placeholder:text-neutral-500 placeholder:font-light"
                        rows=12
                        placeholder="Enter the caption here"
                    ></textarea>
                </div>
                <div class="flex flex-col gap-y-1 mt-2">
                    <label for="hashtag-input" class="mb-1 font-light text-[20px] text-neutral-300">
                        Add Hashtag
                    </label>
                    <Show when=move || {
                        hashtags_err.with(|hashtags_err| !hashtags_err.is_empty())
                    }>
                        <span class="text-sm font-semibold text-red-500">
                            {hashtags_err_memo()}
                        </span>
                    </Show>
                    <input
                        id="hashtag-input"
                        node_ref=hashtag_inp
                        on:input=move |ev| {
                            let hts = event_target_value(&ev);
                            hashtag_on_input(hts);
                        }
                        class="p-3 rounded-lg border transition outline-none focus:border-pink-400 focus:ring-pink-400 bg-neutral-900 border-neutral-800 text-[15px] placeholder:text-neutral-500 placeholder:font-light"
                        type="text"
                        placeholder="Hit enter to add #hashtags"
                    />
                </div>
                {move || {
                    let disa = invalid_form.get();
                    view! {
                        <HighlightedButton
                            on_click=move || on_submit()
                            disabled=disa
                            classes="w-full mx-auto py-[12px] px-[20px] rounded-xl bg-linear-to-r from-pink-300 to-pink-500 text-white font-light text-[17px] transition disabled:opacity-60 disabled:cursor-not-allowed"
                                .to_string()
                        >
                            "Upload"
                        </HighlightedButton>
                    }
                }}
            </div>
        </div>
    }
}

#[component]
pub fn UploadPostPage() -> impl IntoView {
    let trigger_upload = RwSignal::new_local(None::<UploadParams>);
    let uid = RwSignal::new_local(None);
    let upload_file_actual_progress = RwSignal::new(0.0f64);

    view! {
        <Title text="YRAL - Upload" />
        <div class="flex overflow-y-scroll flex-col gap-6 justify-center items-center px-5 pt-4 pb-12 text-white bg-black md:gap-8 md:px-8 md:pt-6 lg:gap-16 lg:px-12 min-h-dvh w-dvw">
            <div class="flex flex-col place-content-center w-full min-h-full lg:flex-row">
                <Show
                    when=move || { trigger_upload.with(|trigger_upload| trigger_upload.is_some()) }
                    fallback=move || {
                        view! {
                            <PreUploadView
                                trigger_upload=trigger_upload.write_only()
                                uid=uid
                                upload_file_actual_progress=upload_file_actual_progress.write_only()
                            />
                        }
                    }
                >

                    <VideoUploader
                        params=trigger_upload.get_untracked().unwrap()
                        uid=uid
                        upload_file_actual_progress=upload_file_actual_progress.read_only()
                    />
                </Show>
            </div>
        </div>
    }
}
