pub mod docker;
pub mod host;
pub mod network;
pub mod packages;
pub mod security;
pub mod storage;
use std::error::Error;

pub trait Scanner: Send {
    fn name(&self) -> &'static str;
    fn scan(&self) -> Result<Box<dyn std::any::Any + Send>, Box<dyn Error + Send>>;
}
