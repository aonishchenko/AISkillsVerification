import type { Bindings, EngagementMetrics } from './types';

/**
 * Minimal X API v2 client using OAuth 1.0a user-context signing (works on
 * Workers via WebCrypto, no SDK). Posting and reading our OWN organic metrics
 * is sanctioned automation; we never touch the website or other users' data.
 */
export class XClient {
  constructor(private readonly env: Bindings) {}

  private creds() {
    const { X_API_KEY, X_API_SECRET, X_ACCESS_TOKEN, X_ACCESS_SECRET } = this.env;
    if (!X_API_KEY || !X_API_SECRET || !X_ACCESS_TOKEN || !X_ACCESS_SECRET) {
      throw new Error('x_credentials_missing');
    }
    return { X_API_KEY, X_API_SECRET, X_ACCESS_TOKEN, X_ACCESS_SECRET };
  }

  async postTweet(text: string): Promise<string> {
    const url = 'https://api.twitter.com/2/tweets';
    const auth = await this.oauthHeader('POST', url, {});
    const res = await fetch(url, {
      method: 'POST',
      headers: { authorization: auth, 'content-type': 'application/json' },
      body: JSON.stringify({ text }),
    });
    if (!res.ok) throw new Error(`x_post_failed_${res.status}:${await res.text()}`);
    const data = (await res.json()) as { data?: { id?: string } };
    if (!data.data?.id) throw new Error('x_post_no_id');
    return data.data.id;
  }

  /** Organic metrics require the OAuth1 user context that owns the tweet. */
  async tweetMetrics(tweetId: string): Promise<EngagementMetrics | null> {
    const base = `https://api.twitter.com/2/tweets/${tweetId}`;
    const params = { 'tweet.fields': 'public_metrics,non_public_metrics,organic_metrics' };
    const qs = new URLSearchParams(params).toString();
    const auth = await this.oauthHeader('GET', base, params);
    const res = await fetch(`${base}?${qs}`, { headers: { authorization: auth } });
    if (!res.ok) return null;
    const data = (await res.json()) as {
      data?: {
        public_metrics?: { like_count: number; reply_count: number; retweet_count: number; quote_count: number; impression_count?: number };
        organic_metrics?: { impression_count: number; like_count: number; reply_count: number; retweet_count: number; user_profile_clicks?: number; url_link_clicks?: number };
        non_public_metrics?: { impression_count: number; user_profile_clicks?: number; url_link_clicks?: number };
      };
    };
    const pub = data.data?.public_metrics;
    const org = data.data?.organic_metrics;
    const np = data.data?.non_public_metrics;
    if (!pub && !org) return null;
    return {
      likes: org?.like_count ?? pub?.like_count ?? 0,
      replies: org?.reply_count ?? pub?.reply_count ?? 0,
      reposts: org?.retweet_count ?? pub?.retweet_count ?? 0,
      quotes: pub?.quote_count ?? 0,
      impressions: org?.impression_count ?? np?.impression_count ?? pub?.impression_count ?? 0,
      profileClicks: org?.user_profile_clicks ?? np?.user_profile_clicks ?? 0,
      urlClicks: org?.url_link_clicks ?? np?.url_link_clicks ?? 0,
    };
  }

  // --- OAuth 1.0a signing -------------------------------------------------

  private async oauthHeader(
    method: string,
    url: string,
    extraParams: Record<string, string>,
  ): Promise<string> {
    const c = this.creds();
    const oauth: Record<string, string> = {
      oauth_consumer_key: c.X_API_KEY,
      oauth_token: c.X_ACCESS_TOKEN,
      oauth_signature_method: 'HMAC-SHA1',
      oauth_timestamp: String(Math.floor(Date.now() / 1000)),
      oauth_nonce: crypto.randomUUID().replace(/-/g, ''),
      oauth_version: '1.0',
    };
    const allParams = { ...oauth, ...extraParams };
    const paramString = Object.keys(allParams)
      .sort()
      .map((k) => `${enc(k)}=${enc(allParams[k])}`)
      .join('&');
    const baseString = `${method.toUpperCase()}&${enc(url)}&${enc(paramString)}`;
    const signingKey = `${enc(c.X_API_SECRET)}&${enc(c.X_ACCESS_SECRET)}`;
    oauth.oauth_signature = await hmacSha1(signingKey, baseString);
    return (
      'OAuth ' +
      Object.keys(oauth)
        .sort()
        .map((k) => `${enc(k)}="${enc(oauth[k])}"`)
        .join(', ')
    );
  }
}

function enc(s: string): string {
  return encodeURIComponent(s).replace(
    /[!*'()]/g,
    (ch) => '%' + ch.charCodeAt(0).toString(16).toUpperCase(),
  );
}

async function hmacSha1(key: string, message: string): Promise<string> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(key),
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign'],
  );
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, new TextEncoder().encode(message));
  return btoa(String.fromCharCode(...new Uint8Array(sig)));
}
