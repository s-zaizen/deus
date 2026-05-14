//! `POST /api/feedback` — low-level TP/FP label endpoint for a single
//! finding. The main UI learning path goes through Review Submit.

use axum::{
    extract::{Extension, Json},
    http::StatusCode,
    response::IntoResponse,
};
use tracing::info;

use crate::api::models::{FeedbackRequest, FeedbackResponse};
use crate::infra::ml::MlClient;
use crate::logging::RequestId;
use crate::store;

pub async fn record(
    Extension(req_id): Extension<RequestId>,
    Json(req): Json<FeedbackRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    store::update_label(&req.finding_id, &req.label.to_string())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let stats =
        store::get_stats().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    info!(
        finding_id = %req.finding_id,
        label = %req.label.to_string(),
        total_labels = stats.total_labels,
        "label recorded"
    );

    if stats.total_labels % 10 == 0 {
        info!(
            total_labels = stats.total_labels,
            "secondary train trigger (every 10 labels)"
        );
        MlClient::new().spawn_train(&req_id.0);
    }

    Ok(Json(FeedbackResponse {
        success: true,
        total_labels: stats.total_labels,
    }))
}
