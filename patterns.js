// BlurShield Pattern Library v2.0
// TRIAL: 32 patterns (core services)
// PRO_ONLY: 23 patterns (advanced services — locked behind Pro)

window.BS_PATTERNS_TRIAL = [
  // ── AWS ──────────────────────────────────────────────────────────────────
  { id:'aws-key-id',     name:'AWS Access Key ID',        service:'AWS',       severity:'critical', confidence:99, pattern:/\b(AKIA|AIPA|AIOA|AIZA|AROA|AIDA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b/g },
  { id:'aws-secret',     name:'AWS Secret Access Key',    service:'AWS',       severity:'critical', confidence:85, pattern:/(?<![A-Za-z0-9/+])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+])/g, contextKeys:['aws_secret','AWS_SECRET','secret_access_key'] },
  { id:'aws-mfa',        name:'AWS MFA Serial',           service:'AWS',       severity:'medium',   confidence:90, pattern:/arn:aws:iam::\d{12}:mfa\/[A-Za-z0-9+=,.@\-_/]+/g },

  // ── GitHub ───────────────────────────────────────────────────────────────
  { id:'gh-pat',         name:'GitHub PAT (Classic)',     service:'GitHub',    severity:'critical', confidence:99, pattern:/ghp_[A-Za-z0-9]{20,}/g },
  { id:'gh-oauth',       name:'GitHub OAuth Token',       service:'GitHub',    severity:'critical', confidence:99, pattern:/gho_[A-Za-z0-9]{20,}/g },
  { id:'gh-fine',        name:'GitHub Fine-Grained Token',service:'GitHub',    severity:'critical', confidence:99, pattern:/github_pat_[A-Za-z0-9_]{20,}/g },
  { id:'gh-app',         name:'GitHub App Token',         service:'GitHub',    severity:'critical', confidence:99, pattern:/gh[usrp]_[A-Za-z0-9]{20,}/g },

  // ── Stripe ───────────────────────────────────────────────────────────────
  { id:'stripe-sk',      name:'Stripe Secret Key',        service:'Stripe',    severity:'critical', confidence:99, pattern:/sk_(live|test)_[A-Za-z0-9]{24,}/g },
  { id:'stripe-pk',      name:'Stripe Publishable Key',   service:'Stripe',    severity:'medium',   confidence:99, pattern:/pk_(live|test)_[A-Za-z0-9]{24,}/g },
  { id:'stripe-webhook', name:'Stripe Webhook Secret',    service:'Stripe',    severity:'high',     confidence:99, pattern:/whsec_[A-Za-z0-9]{32,}/g },

  // ── OpenAI ───────────────────────────────────────────────────────────────
  { id:'openai-key',     name:'OpenAI API Key',           service:'OpenAI',    severity:'critical', confidence:99, pattern:/sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}/g },
  { id:'openai-key-new', name:'OpenAI API Key (new)',     service:'OpenAI',    severity:'critical', confidence:99, pattern:/sk-proj-[A-Za-z0-9\-_]{20,}/g },
  { id:'openai-org',     name:'OpenAI Org ID',            service:'OpenAI',    severity:'medium',   confidence:95, pattern:/org-[A-Za-z0-9]{20,}/g },

  // ── Google ───────────────────────────────────────────────────────────────
  { id:'google-api',     name:'Google API Key',           service:'Google',    severity:'high',     confidence:99, pattern:/AIza[0-9A-Za-z\-_]{35}/g },
  { id:'google-oauth',   name:'Google OAuth Secret',      service:'Google',    severity:'critical', confidence:99, pattern:/GOCSPX-[A-Za-z0-9\-_]{28}/g },

  // ── Slack ─────────────────────────────────────────────────────────────────
  { id:'slack-bot',      name:'Slack Bot Token',          service:'Slack',     severity:'high',     confidence:99, pattern:/xoxb-[0-9]{11}-[0-9]{11}-[A-Za-z0-9]{24}/g },
  { id:'slack-user',     name:'Slack User Token',         service:'Slack',     severity:'high',     confidence:99, pattern:/xoxp-[0-9]{11}-[0-9]{11}-[0-9]{11}-[A-Za-z0-9]{32}/g },
  { id:'slack-webhook',  name:'Slack Webhook URL',        service:'Slack',     severity:'high',     confidence:99, pattern:/https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9]+\/B[A-Za-z0-9]+\/[A-Za-z0-9]+/g },

  // ── Database URLs ─────────────────────────────────────────────────────────
  { id:'db-postgres',    name:'PostgreSQL URL',           service:'Database',  severity:'critical', confidence:99, pattern:/postgres(?:ql)?:\/\/[^:\s]+:[^@\s]+@[^\s"']+/g },
  { id:'db-mysql',       name:'MySQL URL',                service:'Database',  severity:'critical', confidence:99, pattern:/mysql(?:2)?:\/\/[^:\s]+:[^@\s]+@[^\s"']+/g },
  { id:'db-mongo',       name:'MongoDB URL',              service:'Database',  severity:'critical', confidence:99, pattern:/mongodb(?:\+srv)?:\/\/[^:\s]+:[^@\s]+@[^\s"']+/g },
  { id:'db-redis',       name:'Redis URL',                service:'Database',  severity:'high',     confidence:99, pattern:/redis:\/\/:?[^@\s]+@[^\s"']+/g },

  // ── Auth / JWT ────────────────────────────────────────────────────────────
  { id:'jwt',            name:'JWT Token',                service:'Auth',      severity:'high',     confidence:95, pattern:/eyJ[A-Za-z0-9\-_]{10,}\.eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_.+/]+=*/g },
  { id:'bearer',         name:'Bearer Token',             service:'Auth',      severity:'high',     confidence:90, pattern:/Bearer\s+[A-Za-z0-9\-_.~+/]+=*/gi },
  { id:'basic-auth',     name:'Basic Auth URL',           service:'Auth',      severity:'critical', confidence:95, pattern:/https?:\/\/[^:\s]+:[^@\s]+@[^\s"']+/g },

  // ── Private Keys ──────────────────────────────────────────────────────────
  { id:'rsa-private',    name:'RSA Private Key',          service:'Crypto',    severity:'critical', confidence:99, multiline:true, pattern:/-----BEGIN (?:RSA )?PRIVATE KEY-----[\s\S]{50,}?-----END (?:RSA )?PRIVATE KEY-----/g },
  { id:'openssh-private',name:'OpenSSH Private Key',      service:'Crypto',    severity:'critical', confidence:99, multiline:true, pattern:/-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]{50,}?-----END OPENSSH PRIVATE KEY-----/g },

  // ── SendGrid / Twilio ─────────────────────────────────────────────────────
  { id:'sendgrid',       name:'SendGrid API Key',         service:'SendGrid',  severity:'high',     confidence:99, pattern:/SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}/g },
  { id:'twilio-sid',     name:'Twilio Account SID',       service:'Twilio',    severity:'high',     confidence:95, pattern:/AC[a-z0-9]{32}/g },

  // ── PII ───────────────────────────────────────────────────────────────────
  { id:'email',          name:'Email Address',            service:'PII',       severity:'low',      confidence:95, pattern:/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g },
  { id:'phone',          name:'Phone Number',             service:'PII',       severity:'low',      confidence:80, pattern:/(?:\+?[1-9]\d{1,3}[\s.\-]?)?(?:\(?\d{3,5}\)?[\s.\-]?\d{3,5}[\s.\-]?\d{3,5})(?![\d])(?=\s|$|[^\d])/g },
  { id:'creditcard',     name:'Credit Card Number',       service:'PII',       severity:'critical', confidence:85, pattern:/\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b/g },

  // ── Generic secrets ───────────────────────────────────────────────────────
  { id:'generic-secret', name:'Secret / API Key (env)',   service:'Generic',   severity:'medium',   confidence:70, pattern:/(?:SECRET|PASSWORD|PASSWD|API_KEY|APIKEY|TOKEN|ACCESS_TOKEN)\s*[=:]\s*["']?([A-Za-z0-9+/=_\-]{20,})["']?/gi },
];

// PRO-ONLY patterns — only loaded when isPro=true or trial active with proPatterns flag
window.BS_PATTERNS_PRO = [
  // ── Anthropic ─────────────────────────────────────────────────────────────
  { id:'anthropic-key',  name:'Anthropic API Key',        service:'Anthropic', severity:'critical', confidence:99, pattern:/sk-ant-(?:api03-)?[A-Za-z0-9\-_]{20,}/g },

  // ── HuggingFace / Cohere ──────────────────────────────────────────────────
  { id:'huggingface',    name:'HuggingFace Token',        service:'HuggingFace',severity:'high',   confidence:99, pattern:/hf_[A-Za-z0-9]{20,}/g },
  { id:'cohere-key',     name:'Cohere API Key',           service:'Cohere',    severity:'critical', confidence:85, pattern:/[A-Za-z0-9]{30,}/g, contextKeys:['COHERE_API_KEY','cohere_key'] },

  // ── Stripe extras ─────────────────────────────────────────────────────────
  { id:'stripe-rk',      name:'Stripe Restricted Key',   service:'Stripe',    severity:'high',     confidence:99, pattern:/rk_(live|test)_[A-Za-z0-9]{24,}/g },
  { id:'stripe-acct',    name:'Stripe Account ID',        service:'Stripe',    severity:'low',      confidence:95, pattern:/\bacct_[A-Za-z0-9]{14,}\b/g },

  // ── Discord ───────────────────────────────────────────────────────────────
  { id:'discord-token',  name:'Discord Bot Token',        service:'Discord',   severity:'critical', confidence:90, pattern:/[MN][A-Za-z0-9]{23}\.[\w-]{6}\.[\w-]{27}/g },
  { id:'discord-webhook',name:'Discord Webhook',          service:'Discord',   severity:'high',     confidence:99, pattern:/https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_\-]+/g },

  // ── Cloud providers ───────────────────────────────────────────────────────
  { id:'do-token',       name:'DigitalOcean Token',       service:'DigitalOcean',severity:'critical',confidence:85,pattern:/dop_v1_[a-z0-9]{64}/g },
  { id:'heroku-key',     name:'Heroku API Key',           service:'Heroku',    severity:'critical', confidence:90, pattern:/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g, contextKeys:['HEROKU_API_KEY'] },
  { id:'cloudflare-token',name:'Cloudflare API Token',   service:'Cloudflare',severity:'critical', confidence:99, pattern:/[A-Za-z0-9_\-]{40}/g, contextKeys:['CLOUDFLARE_API_TOKEN'] },

  // ── GitLab ────────────────────────────────────────────────────────────────
  { id:'gitlab-pat',     name:'GitLab PAT',               service:'GitLab',    severity:'critical', confidence:99, pattern:/glpat-[A-Za-z0-9\-_]{20}/g },
  { id:'gitlab-pipeline',name:'GitLab Pipeline Token',   service:'GitLab',    severity:'high',     confidence:99, pattern:/glptt-[A-Za-z0-9]{40}/g },

  // ── Payments ──────────────────────────────────────────────────────────────
  { id:'razorpay-key',   name:'Razorpay Key ID',          service:'Razorpay',  severity:'high',     confidence:99, pattern:/rzp_(live|test)_[A-Za-z0-9]{14}/g },
  { id:'braintree-key',  name:'Braintree Access Token',   service:'Braintree', severity:'critical', confidence:99, pattern:/access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}/g },

  // ── Monitoring ────────────────────────────────────────────────────────────
  { id:'sentry-dsn',     name:'Sentry DSN',               service:'Sentry',    severity:'medium',   confidence:99, pattern:/https:\/\/[a-z0-9]{32}@[a-z0-9]+\.ingest\.sentry\.io\/\d+/g },
  { id:'datadog-key',    name:'Datadog API Key',          service:'Datadog',   severity:'high',     confidence:90, pattern:/[a-z0-9]{32}/g, contextKeys:['DD_API_KEY','DATADOG_API_KEY'] },

  // ── Comms ─────────────────────────────────────────────────────────────────
  { id:'twilio-key',     name:'Twilio Auth Token',        service:'Twilio',    severity:'critical', confidence:90, pattern:/SK[a-z0-9]{32}/g },
  { id:'mailgun',        name:'Mailgun API Key',          service:'Mailgun',   severity:'high',     confidence:90, pattern:/key-[0-9a-zA-Z]{32}/g },

  // ── PII extras ────────────────────────────────────────────────────────────

  // ── Crypto extras ─────────────────────────────────────────────────────────
  { id:'ec-private',     name:'EC Private Key',           service:'Crypto',    severity:'critical', confidence:99, multiline:true, pattern:/-----BEGIN EC PRIVATE KEY-----[\s\S]{50,}?-----END EC PRIVATE KEY-----/g },
  { id:'pgp-private',    name:'PGP Private Key',          service:'Crypto',    severity:'critical', confidence:99, multiline:true, pattern:/-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]{50,}?-----END PGP PRIVATE KEY BLOCK-----/g },

  // ── Firebase / Supabase ───────────────────────────────────────────────────
  { id:'firebase-key',   name:'Firebase API Key',         service:'Firebase',  severity:'high',     confidence:90, pattern:/AIza[0-9A-Za-z\-_]{35}/g, contextKeys:['FIREBASE'] },
  { id:'db-supabase',    name:'Supabase Service Key',     service:'Supabase',  severity:'critical', confidence:99, pattern:/eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+/g, contextKeys:['SUPABASE_KEY','service_role'] },
];

// Active patterns — set by subscription system
window.BS_PATTERNS = [...window.BS_PATTERNS_TRIAL];

window.BS_SEVERITY = {
  critical: { bg:'#300a0a', border:'#7f1d1d', badge:'#fca5a5', dot:'#ef4444', label:'Critical' },
  high:     { bg:'#2d1b00', border:'#78350f', badge:'#fcd34d', dot:'#f59e0b', label:'High' },
  medium:   { bg:'#1a1040', border:'#3730a3', badge:'#a5b4fc', dot:'#818cf8', label:'Medium' },
  low:      { bg:'#002818', border:'#14532d', badge:'#86efac', dot:'#22c55e', label:'Low' },
};

window.BS_CATEGORIES = {
  AWS:'☁', GitHub:'', Stripe:'💳', OpenAI:'◆', Anthropic:'◈',
  Google:'⬡', Firebase:'🔥', Slack:'#', Discord:'⟡', Database:'⬡',
  Auth:'🔑', Crypto:'🔐', PII:'👤', Generic:'⚙', Default:'◉'
};
