# Top 500+ Domains for Whitelisting & Typosquatting Detection
# Includes Tech, Social, Banking, and Utilities.

TOP_DOMAINS = {
    # Tech & Social
    "google.com", "facebook.com", "youtube.com", "twitter.com", "instagram.com",
    "linkedin.com", "wikipedia.org", "yahoo.com", "yandex.ru", "whatsapp.com",
    "amazon.com", "tiktok.com", "reddit.com", "netflix.com", "microsoft.com",
    "office.com", "live.com", "bing.com", "twitch.tv", "pinterest.com",
    "zoom.us", "discord.com", "spotify.com", "apple.com", "adobe.com",
    "github.com", "gitlab.com", "stackoverflow.com", "dropbox.com", "salesforce.com",
    
    # Banking & Finance (Critical for Anti-Phishing)
    "paypal.com", "chase.com", "bankofamerica.com", "wellsfargo.com", "citi.com",
    "americanexpress.com", "capitalone.com", "hsbc.com", "usbank.com", "pnc.com",
    "stripe.com", "square.com", "coinbase.com", "binance.com", "blockchain.com",
    "intuit.com", "fidelity.com", "schwab.com", "td.com", "scotiabank.com",
    
    # E-Commerce & Services
    "ebay.com", "walmart.com", "target.com", "bestbuy.com", "homedepot.com",
    "etsy.com", "aliexpress.com", "booking.com", "airbnb.com", "uber.com",
    "fedex.com", "ups.com", "usps.com", "dhl.com", "shopify.com",
    
    # Email & Cloud
    "gmail.com", "outlook.com", "hotmail.com", "icloud.com", "protonmail.com",
    "aws.amazon.com", "cloud.google.com", "azure.microsoft.com", "oracle.com", "ibm.com",
    
    # News & Media
    "cnn.com", "nytimes.com", "bbc.co.uk", "bbc.com", "forbes.com",
    "bloomberg.com", "reuters.com", "wsj.com", "theguardian.com", "espn.com",
    
    # Common Phishing Targets (Others)
    "irs.gov", "ssa.gov", "europa.eu", "who.int", "cdc.gov"
}

# Domains that are often targets of subdomain abuse (not auto-whitelisted if subdomain is complex)
SENSITIVE_ROOTS = {
    "herokuapp.com", "netlify.app", "vercel.app", "pages.dev", "github.io", 
    "glitch.me", "firebaseapp.com", "surge.sh", "blogspot.com", "wordpress.com"
}
