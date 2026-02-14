use std::str::FromStr;
use serde::{Deserialize, Serialize};
use stripe::{Client, StripeError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillingInfo {
    // Placeholder for Stripe/provider details
    pub customer_id: Option<String>,
    pub subscription_id: Option<String>,
    pub status: SubscriptionStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionStatus {
    Active,
    PastDue,
    Canceled,
    Unpaid,
    Incomplete,
    Trialing,
    None,
}

impl Default for SubscriptionStatus {
    fn default() -> Self {
        Self::None
    }
}

pub struct BillingService {
    client: Client,
}

impl BillingService {
    pub fn new(secret_key: String) -> Self {
        Self {
            client: Client::new(secret_key),
        }
    }
    
    pub async fn create_customer(&self, email: &str, name: &str) -> Result<stripe::Customer, StripeError> {
        let params = stripe::CreateCustomer {
            email: Some(email),
            name: Some(name),
            ..Default::default()
        };
        stripe::Customer::create(&self.client, params).await
    }
    
    pub async fn get_subscription(&self, sub_id: &str) -> Result<stripe::Subscription, StripeError> {
        stripe::Subscription::retrieve(&self.client, &stripe::SubscriptionId::from_str(sub_id).unwrap(), &[]).await
    }
}
