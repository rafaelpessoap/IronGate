use axum::{
    http::header,
    response::{Html, IntoResponse},
};

pub async fn index_html() -> Html<&'static str> {
    Html(include_str!("../../static/index.html"))
}

pub async fn style_css() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css")],
        include_str!("../../static/style.css"),
    )
}

pub async fn app_js() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "application/javascript")],
        include_str!("../../static/app.js"),
    )
}
