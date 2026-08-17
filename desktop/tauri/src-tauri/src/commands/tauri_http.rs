use serde::{Deserialize, Serialize};
use tauri::State;

#[cfg(target_os = "linux")]
use bytes::Bytes;
#[cfg(target_os = "linux")]
use http_body_util::{BodyExt, Full};
#[cfg(target_os = "linux")]
use hyper::body::Incoming;
#[cfg(target_os = "linux")]
use hyper_util::client::legacy::Client;
#[cfg(target_os = "linux")]
use hyperlocal::{UnixClientExt, UnixConnector, Uri};

#[cfg(not(target_os = "linux"))]
use reqwest::{Client, Method};

#[cfg(target_os = "linux")]
pub type HttpClient = Client<UnixConnector, Full<Bytes>>;
#[cfg(not(target_os = "linux"))]
pub type HttpClient = Client;

/// Creates the HTTP client used by the native Filemaster UI. On Linux it
/// connects directly to the core's Unix-domain socket.
pub fn create_http_client() -> HttpClient {
    #[cfg(target_os = "linux")]
    {
        HttpClient::unix()
    }

    #[cfg(not(target_os = "linux"))]
    {
        Client::builder()
            .pool_max_idle_per_host(10)
            .cookie_store(true)
            .user_agent("Filemaster UI")
            .build()
            .expect("failed to build HTTP client")
    }
}

#[derive(Deserialize)]
pub struct HttpRequestOptions {
    method: String,
    headers: Vec<(String, String)>,
    body: Option<Vec<u8>>,
}

#[derive(Debug, Serialize)]
pub struct HttpResponse {
    status: u16,
    status_text: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

#[cfg(target_os = "linux")]
async fn send_api_request(
    client: &HttpClient,
    method: http::Method,
    path: &str,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
) -> Result<HttpResponse, String> {
    if !path.starts_with('/') {
        return Err("API request path must start with '/'".to_string());
    }

    let uri: hyper::Uri = Uri::new(crate::portmaster::API_SOCKET_PATH, path).into();
    let mut request = http::Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        request = request.header(name, value);
    }
    let request = request
        .body(Full::new(Bytes::from(body)))
        .map_err(|err| err.to_string())?;
    let response = client
        .request(request)
        .await
        .map_err(|err| err.to_string())?;
    response_from_hyper(response).await
}

#[cfg(target_os = "linux")]
async fn response_from_hyper(response: http::Response<Incoming>) -> Result<HttpResponse, String> {
    let status = response.status();
    let headers = response
        .headers()
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_str().unwrap_or("").to_string()))
        .collect();
    let body = response
        .into_body()
        .collect()
        .await
        .map_err(|err| err.to_string())?
        .to_bytes()
        .to_vec();

    Ok(HttpResponse {
        status: status.as_u16(),
        status_text: status.canonical_reason().unwrap_or("").to_string(),
        headers,
        body,
    })
}

#[cfg(target_os = "linux")]
pub async fn post_api(path: &str, body: Vec<u8>) -> Result<HttpResponse, String> {
    let client = create_http_client();
    send_api_request(&client, http::Method::POST, path, Vec::new(), body).await
}

#[cfg(not(target_os = "linux"))]
pub async fn post_api(path: &str, body: Vec<u8>) -> Result<HttpResponse, String> {
    let url = format!("http://{}{}", crate::portmaster::api_address(), path);
    let response = create_http_client()
        .post(url)
        .body(body)
        .send()
        .await
        .map_err(|err| err.to_string())?;
    let status = response.status();
    let headers = response
        .headers()
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_str().unwrap_or("").to_string()))
        .collect();
    let body = response
        .bytes()
        .await
        .map_err(|err| err.to_string())?
        .to_vec();
    Ok(HttpResponse {
        status: status.as_u16(),
        status_text: status.canonical_reason().unwrap_or("").to_string(),
        headers,
        body,
    })
}

#[tauri::command]
pub async fn send_tauri_http_request(
    client: State<'_, HttpClient>,
    url: String,
    opts: HttpRequestOptions,
) -> Result<HttpResponse, String> {
    #[cfg(target_os = "linux")]
    {
        let path = crate::portmaster::api_request_path(&url)?;
        let method =
            http::Method::from_bytes(opts.method.as_bytes()).map_err(|err| err.to_string())?;
        return send_api_request(
            &client,
            method,
            &path,
            opts.headers,
            opts.body.unwrap_or_default(),
        )
        .await;
    }

    #[cfg(not(target_os = "linux"))]
    {
        let mut request = client.request(
            Method::from_bytes(opts.method.as_bytes()).map_err(|err| err.to_string())?,
            &url,
        );
        for (name, value) in opts.headers {
            request = request.header(name, value);
        }
        if let Some(body) = opts.body {
            request = request.body(body);
        }
        let response = request.send().await.map_err(|err| err.to_string())?;
        let status = response.status();
        let headers = response
            .headers()
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_str().unwrap_or("").to_string()))
            .collect();
        let body = response
            .bytes()
            .await
            .map_err(|err| err.to_string())?
            .to_vec();
        Ok(HttpResponse {
            status: status.as_u16(),
            status_text: status.canonical_reason().unwrap_or("").to_string(),
            headers,
            body,
        })
    }
}
