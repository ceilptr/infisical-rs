use secrecy::{zeroize::Zeroize, ExposeSecret, SecretBox, SerializableSecret};
use serde::{Deserialize, Serialize};

use super::auth_methods::universal_auth::utils::*;
// use serde_with::serde_as;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct InfisicalSecretTag {
    color: String,
    id: String,
    name: String,
    slug: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct InfisicalSecretMetadata {
    pub key: String,
    pub value: String,
}

// #[serde_as]
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all(serialize = "snake_case", deserialize = "camelCase"))]
pub struct InfisicalSecretData {
    #[serde(rename(serialize = "u_id", deserialize = "_id"))]
    pub u_id: String,
    pub created_at: String,
    pub environment: String,
    pub id: String,
    // #[serde_as(as = "DefaultOnNull")]
    // pub metadata: Option<String>,
    pub secret_comment: String,
    pub secret_key: String,
    pub secret_metadata: Vec<InfisicalSecretMetadata>,
    pub secret_reminder_note: String,
    pub secret_reminder_repeat_days: u64,
    pub secret_value: String,
    pub skip_multiline_encoding: Option<bool>,
    pub tags: Vec<InfisicalSecretTag>,
    #[serde(rename(serialize = "type_", deserialize = "type"))]
    pub type_: String,
    pub updated_at: String,
    pub version: u64,
    pub workspace: String,
}

//secrecy create boilerplate
impl SerializableSecret for InfisicalSecretData {}

impl Zeroize for InfisicalSecretData {
    fn zeroize(&mut self) {
        self.u_id.zeroize();
        self.created_at.zeroize();
        self.environment.zeroize();
        self.id.zeroize();
        self.secret_comment.zeroize();
        self.secret_key.zeroize();
        self.secret_metadata.zeroize();
        self.secret_reminder_note.zeroize();
        self.secret_reminder_repeat_days.zeroize();
        self.secret_value.zeroize();
        self.skip_multiline_encoding.zeroize();
        self.tags.zeroize();
        self.type_.zeroize();
        self.updated_at.zeroize();
        self.version.zeroize();
        self.workspace.zeroize();
    }
}

impl Zeroize for InfisicalSecretMetadata {
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.value.zeroize();
    }
}

impl Zeroize for InfisicalSecretTag {
    fn zeroize(&mut self) {
        self.color.zeroize();
        self.id.zeroize();
        self.name.zeroize();
        self.slug.zeroize();
    }
}

#[derive(Serialize, Deserialize)]
pub struct InfisicalSecret {
    pub data: SecretBox<InfisicalSecretData>,
}

// mainly just convenience functions
impl InfisicalSecret {
    pub fn get_secret_metadata(&self, metadata_key: &str) -> Vec<InfisicalSecretMetadata> {
        self.data
            .expose_secret()
            .secret_metadata
            .clone()
            .into_iter()
            .filter(|metadata_entry| metadata_entry.key == metadata_key)
            .collect()
    }

    pub fn search_tags(
        &self,
        tag_id: Option<&str>,
        tag_color: Option<&str>,
        tag_name: Option<&str>,
        tag_slug: Option<&str>,
    ) -> Vec<InfisicalSecretTag> {
        self.data
            .expose_secret()
            .tags
            .clone()
            .into_iter()
            .filter(|entry| match tag_id {
                // if the user specified a tag ig, we can assume they mean to return a single specific tag
                // otherwise, we can't necessarily (i think) assume a tag color, name, or slug are unique
                // so we return a vec of tags and match on whatever user input
                Some(specific_id) => entry.id.eq(specific_id),
                None => {
                    entry.color.eq(tag_color.unwrap_or_default())
                        || entry.name.eq(tag_name.unwrap_or_default())
                        || entry.slug.eq(tag_slug.unwrap_or_default())
                }
            })
            .collect()
    }
}

pub async fn get_secret(
    client: &reqwest::Client,
    access_token: &UniversalAuthAccessToken,
    host: &str,
    secret: &str,
    environment: Option<&str>,
    workspace_id: &str,
    secret_path: Option<&str>,
    // ) -> Result<InfisicalSecret, Box<dyn std::error::Error>> {
) -> Result<InfisicalSecret, Box<dyn std::error::Error>> {
    let api_request: serde_json::Value = client
          .get(format!(
              "{host}/api/{endpoint_api_version}/{endpoint}/{secret}?workspaceId={workspace_id}&environment={secret_environment}&secretPath={secret_path}",
              host = host,
              endpoint_api_version = "v3",
              endpoint = "secrets/raw",
              secret = secret,
              workspace_id = workspace_id,
              secret_environment = environment.unwrap_or_else(|| ""),
              secret_path=secret_path.unwrap_or_else(|| "/")
          ))
          .bearer_auth(&access_token.access_token())
          .send()
        .await?
          .json().await?;

    // holy shit thank you: https://users.rust-lang.org/t/how-does-ok-or-and-question-mark-convert-str-into-an-error/46643
    let secrets_obj = api_request
        .as_object()
        .ok_or_else(|| "couldn't return secret object")?
        .get("secret")
        .ok_or_else(|| "couldn't extract inner secret object")?;

    // deserialize inner object to InfisicalSecret struct and return (or don't, if some goes horrendously wrong)
    // match serde_json::from_value::<InfisicalSecret>(secrets_obj.clone()) {
    match serde_json::from_value::<InfisicalSecretData>(secrets_obj.clone()) {
        Ok(secret_struct) => {
            // println!("get_secret: {:#?}", secret_struct);
            return Ok(InfisicalSecret {
                data: SecretBox::new(Box::new(secret_struct)),
            });
        }
        Err(e) => {
            // println!("get_secret error: {}", e);
            return Err(Box::new(e));
        }
    }
}
