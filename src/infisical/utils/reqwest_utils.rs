use reqwest::Response;
use unescaper::unescape;

use super::api_utils::ApiResponse;

pub fn reqwest_bytes_to_unescaped_string(
    bytes: &[u8],
) -> Result<String, Box<dyn std::error::Error>> {
    let unescaped = unescape(&bytes.escape_ascii().to_string())?;

    // let filtered_bytes = unescaped.replace(",", "\n");

    Ok(unescaped.to_string())
}

pub async fn reqwest_error_to_struct(
    response: Response,
    // ) -> Result<impl ApiResponseTrait, Box<dyn std::error::Error>> {
) -> Result<ApiResponse, Box<dyn std::error::Error>> {
    let f = response.json::<ApiResponse>().await?;
    Ok(f)
}

#[derive(thiserror::Error, Debug)]
pub enum RequestUtilsError {
    #[error("owch: {err:#?}")]
    UnescapeByteStringError { err: unescaper::Error },
}
