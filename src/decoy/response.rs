use http::{
    Response, StatusCode,
    header::{CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, HeaderValue},
};

use crate::proxy::{ProxyBody, full_body};

#[derive(Clone)]
struct Local {
    content_type: &'static str,
    length: usize,
}

pub(super) fn response(
    status: StatusCode,
    body: String,
    json: bool,
    head: bool,
) -> Response<ProxyBody> {
    let length = body.len();
    let mut response = Response::new(full_body(if head { String::new() } else { body }));
    *response.status_mut() = status;
    response.extensions_mut().insert(Local {
        content_type: if json {
            "application/json"
        } else {
            "text/plain; charset=utf-8"
        },
        length,
    });
    if status == StatusCode::UNAUTHORIZED {
        response.headers_mut().insert(
            "www-authenticate",
            HeaderValue::from_static("Bearer realm=\"internal-api\""),
        );
    }
    finalize(&mut response);
    response
}

pub(crate) fn finalize(response: &mut Response<ProxyBody>) {
    let Some(local) = response.extensions().get::<Local>().cloned() else {
        return;
    };
    let unauthorized = response.status() == StatusCode::UNAUTHORIZED;
    let headers = response.headers_mut();
    for name in [
        "etag",
        "last-modified",
        "age",
        "content-encoding",
        "content-range",
        "accept-ranges",
        "set-cookie",
        "location",
        "refresh",
        "link",
        "content-location",
        "www-authenticate",
    ] {
        headers.remove(name);
    }
    let cors = headers
        .keys()
        .filter(|name| name.as_str().starts_with("access-control-"))
        .cloned()
        .collect::<Vec<_>>();
    for name in cors {
        headers.remove(name);
    }
    if unauthorized {
        headers.insert(
            "www-authenticate",
            HeaderValue::from_static("Bearer realm=\"internal-api\""),
        );
    }
    for (name, value) in [
        (CACHE_CONTROL.as_str(), "no-store"),
        ("x-robots-tag", "noindex, nofollow"),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        (CONTENT_TYPE.as_str(), local.content_type),
    ] {
        headers.insert(
            http::header::HeaderName::from_static(name),
            HeaderValue::from_static(value),
        );
    }
    if let Ok(length) = HeaderValue::from_str(&local.length.to_string()) {
        headers.insert(CONTENT_LENGTH, length);
    }
}
