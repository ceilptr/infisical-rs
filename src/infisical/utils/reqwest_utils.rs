pub mod string_formatting {
    use unescaper::unescape;

    ///
    /// there has to be a cleaner way to do this but this will work for now
    pub fn reqwest_bytes_to_unescaped_string(
        bytes: &[u8],
    ) -> Result<String, Box<dyn std::error::Error>> {
        let unescaped = unescape(&bytes.escape_ascii().to_string())?;

        let filtered_bytes = unescaped.replace(",", "\n");

        Ok(filtered_bytes)
    }
}

pub mod reqwest_error_handling {
    use reqwest::{Response, StatusCode};

    use crate::infisical::utils::api_response::ApiResponseEnum;

    pub async fn reqwest_error_to_struct(
        response: Response,
        // ) -> Result<impl ApiResponseTrait, Box<dyn std::error::Error>> {
    ) -> Result<ApiResponseEnum, Box<dyn std::error::Error>> {
        let f = response.json::<ApiResponseEnum>().await?;
        Ok(f)
    }

    // pub async fn reqwest_error_to_struct2(
    //     response: Response,
    // ) -> Result<Box<dyn ApiResponseTrait>, Box<dyn std::error::Error>> {
    //     // match response.status() {
    //     //     StatusCode::OK => Ok(response.json::<OkApiResponse>().await?),
    //     //     StatusCode::BAD_REQUEST => Ok(response.json::<BadApiResponse>().await?),
    //     //     _ => todo!(),
    //     // }

    //     match response.status() {
    //         StatusCode::OK => Ok(Box::new(response.json::<OkApiResponse>().await?)),
    //         StatusCode::BAD_REQUEST => Ok(Box::new(response.json::<BadApiResponse>().await?)),
    //         StatusCode::UNAUTHORIZED => {
    //             Ok(Box::new(response.json::<UnauthorizedApiResponse>().await?))
    //         }
    //         StatusCode::FORBIDDEN => Ok(Box::new(response.json::<ForbiddenApiResponse>().await?)),
    //         StatusCode::NOT_FOUND => Ok(Box::new(response.json::<NotFoundApiResponse>().await?)),
    //         StatusCode::UNPROCESSABLE_ENTITY => Ok(Box::new(
    //             response.json::<UnprocessableContentApiResponse>().await?,
    //         )),
    //         StatusCode::INTERNAL_SERVER_ERROR => Ok(Box::new(
    //             response.json::<InternalServerErrorApiResponse>().await?,
    //         )),
    //         // StatusCode::BAD_REQUEST => Ok(Box::new(response.json::<BadApiResponse>().await?)),
    //         _ => Ok(Box::new(EmptyApiResponse {})),
    //     }
    // }
}
