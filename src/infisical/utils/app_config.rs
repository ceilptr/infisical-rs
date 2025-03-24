// pub mod app_config;
pub struct AppConfig {
    pub host: String,
    pub client: reqwest::Client,
    // pub client: reqwest::blocking::Client,
}
