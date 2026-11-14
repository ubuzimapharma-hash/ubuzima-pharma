CREATE TABLE IF NOT EXISTS staff_users (
  id UUID PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'admin' CHECK (role IN ('admin', 'pharmacist', 'doctor')),
  full_name VARCHAR(120) NOT NULL DEFAULT '',
  phone VARCHAR(30) NOT NULL DEFAULT '',
  profile_image_url TEXT,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE staff_users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'admin';
ALTER TABLE staff_users ADD COLUMN IF NOT EXISTS full_name VARCHAR(120) NOT NULL DEFAULT '';
ALTER TABLE staff_users ADD COLUMN IF NOT EXISTS phone VARCHAR(30) NOT NULL DEFAULT '';
ALTER TABLE staff_users ADD COLUMN IF NOT EXISTS profile_image_url TEXT;
ALTER TABLE staff_users ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE staff_users DROP CONSTRAINT IF EXISTS staff_users_role_check;
ALTER TABLE staff_users ADD CONSTRAINT staff_users_role_check CHECK (role IN ('admin', 'pharmacist', 'doctor'));

CREATE TABLE IF NOT EXISTS products (
  id UUID PRIMARY KEY,
  name VARCHAR(120) NOT NULL,
  category VARCHAR(80) NOT NULL,
  description VARCHAR(500) NOT NULL,
  price_bif NUMERIC(12, 0) CHECK (price_bif IS NULL OR price_bif >= 0),
  stock_quantity INTEGER NOT NULL DEFAULT 0 CHECK (stock_quantity >= 0),
  image_url TEXT NOT NULL,
  is_available BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE products ADD COLUMN IF NOT EXISTS stock_quantity INTEGER NOT NULL DEFAULT 0;
ALTER TABLE products DROP CONSTRAINT IF EXISTS products_stock_quantity_check;
ALTER TABLE products ADD CONSTRAINT products_stock_quantity_check CHECK (stock_quantity >= 0);
ALTER TABLE products ADD COLUMN IF NOT EXISTS generic_name VARCHAR(120);
ALTER TABLE products ADD COLUMN IF NOT EXISTS active_ingredient VARCHAR(300);
ALTER TABLE products ADD COLUMN IF NOT EXISTS strength VARCHAR(80);
ALTER TABLE products ADD COLUMN IF NOT EXISTS dosage_form VARCHAR(80);
ALTER TABLE products ADD COLUMN IF NOT EXISTS pack_size VARCHAR(120);
ALTER TABLE products ADD COLUMN IF NOT EXISTS manufacturer VARCHAR(120);
ALTER TABLE products ADD COLUMN IF NOT EXISTS directions_for_use TEXT;
ALTER TABLE products ADD COLUMN IF NOT EXISTS indications TEXT;
ALTER TABLE products ADD COLUMN IF NOT EXISTS warnings TEXT;
ALTER TABLE products ADD COLUMN IF NOT EXISTS storage_instructions VARCHAR(500);

CREATE INDEX IF NOT EXISTS products_public_catalogue_idx
  ON products (is_available, name);

CREATE TABLE IF NOT EXISTS patient_users (
  id UUID PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  full_name VARCHAR(120) NOT NULL,
  phone VARCHAR(30) NOT NULL,
  profile_image_url TEXT,
  password_hash TEXT NOT NULL,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE patient_users ADD COLUMN IF NOT EXISTS profile_image_url TEXT;

CREATE TABLE IF NOT EXISTS password_reset_tokens (
  id UUID PRIMARY KEY,
  token_hash TEXT NOT NULL UNIQUE,
  staff_user_id UUID REFERENCES staff_users(id) ON DELETE CASCADE,
  patient_user_id UUID REFERENCES patient_users(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL,
  used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK (
    (staff_user_id IS NOT NULL AND patient_user_id IS NULL) OR
    (staff_user_id IS NULL AND patient_user_id IS NOT NULL)
  )
);

CREATE INDEX IF NOT EXISTS password_reset_tokens_staff_idx
  ON password_reset_tokens (staff_user_id, created_at DESC) WHERE used_at IS NULL;
CREATE INDEX IF NOT EXISTS password_reset_tokens_patient_idx
  ON password_reset_tokens (patient_user_id, created_at DESC) WHERE used_at IS NULL;

CREATE TABLE IF NOT EXISTS patient_orders (
  id UUID PRIMARY KEY,
  patient_id UUID NOT NULL REFERENCES patient_users(id) ON DELETE RESTRICT,
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'confirmed', 'ready', 'completed', 'cancelled')),
  total_bif NUMERIC(14, 0) NOT NULL CHECK (total_bif >= 0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS patient_orders_patient_created_idx
  ON patient_orders (patient_id, created_at DESC);
CREATE INDEX IF NOT EXISTS patient_orders_status_created_idx
  ON patient_orders (status, created_at DESC);

CREATE TABLE IF NOT EXISTS patient_care_requests (
  id UUID PRIMARY KEY,
  patient_id UUID NOT NULL REFERENCES patient_users(id) ON DELETE CASCADE,
  treatment_location VARCHAR(180) NOT NULL,
  treated_on DATE NOT NULL,
  prescription_filename TEXT,
  prescription_mime_type TEXT,
  status TEXT NOT NULL DEFAULT 'open'
    CHECK (status IN ('open', 'in_progress', 'closed')),
  doctor_consultation_status TEXT NOT NULL DEFAULT 'not_requested'
    CHECK (doctor_consultation_status IN ('not_requested', 'requested', 'assigned', 'contacted', 'scheduled', 'completed')),
  assigned_doctor_id UUID REFERENCES staff_users(id) ON DELETE SET NULL,
  doctor_scheduled_at TIMESTAMPTZ,
  doctor_duration_minutes SMALLINT NOT NULL DEFAULT 30 CHECK (doctor_duration_minutes BETWEEN 15 AND 120),
  doctor_meeting_url TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS patient_care_requests_patient_created_idx
  ON patient_care_requests (patient_id, created_at DESC);
CREATE INDEX IF NOT EXISTS patient_care_requests_status_updated_idx
  ON patient_care_requests (status, updated_at DESC);

ALTER TABLE patient_care_requests ADD COLUMN IF NOT EXISTS assigned_doctor_id UUID REFERENCES staff_users(id) ON DELETE SET NULL;
ALTER TABLE patient_care_requests ADD COLUMN IF NOT EXISTS doctor_scheduled_at TIMESTAMPTZ;
ALTER TABLE patient_care_requests ADD COLUMN IF NOT EXISTS doctor_duration_minutes SMALLINT NOT NULL DEFAULT 30;
ALTER TABLE patient_care_requests ADD COLUMN IF NOT EXISTS doctor_meeting_url TEXT;
ALTER TABLE patient_care_requests DROP CONSTRAINT IF EXISTS patient_care_requests_doctor_consultation_status_check;
ALTER TABLE patient_care_requests ADD CONSTRAINT patient_care_requests_doctor_consultation_status_check
  CHECK (doctor_consultation_status IN ('not_requested', 'requested', 'assigned', 'contacted', 'scheduled', 'completed'));
CREATE INDEX IF NOT EXISTS patient_care_requests_doctor_schedule_idx
  ON patient_care_requests (assigned_doctor_id, doctor_scheduled_at)
  WHERE assigned_doctor_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS doctor_call_signals (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  care_request_id UUID NOT NULL REFERENCES patient_care_requests(id) ON DELETE CASCADE,
  sender_role TEXT NOT NULL CHECK (sender_role IN ('patient', 'doctor')),
  recipient_role TEXT NOT NULL CHECK (recipient_role IN ('patient', 'doctor')),
  signal JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK (sender_role <> recipient_role)
);

CREATE INDEX IF NOT EXISTS doctor_call_signals_recipient_idx
  ON doctor_call_signals (care_request_id, recipient_role, id);

CREATE TABLE IF NOT EXISTS patient_care_messages (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  request_id UUID NOT NULL REFERENCES patient_care_requests(id) ON DELETE CASCADE,
  sender_patient_id UUID REFERENCES patient_users(id) ON DELETE SET NULL,
  sender_staff_id UUID REFERENCES staff_users(id) ON DELETE SET NULL,
  message TEXT NOT NULL CHECK (length(message) BETWEEN 1 AND 4000),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK ((sender_patient_id IS NOT NULL AND sender_staff_id IS NULL) OR
         (sender_patient_id IS NULL AND sender_staff_id IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS patient_care_messages_request_idx
  ON patient_care_messages (request_id, created_at, id);

CREATE TABLE IF NOT EXISTS doctor_consultation_messages (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  care_request_id UUID NOT NULL REFERENCES patient_care_requests(id) ON DELETE CASCADE,
  sender_patient_id UUID REFERENCES patient_users(id) ON DELETE SET NULL,
  sender_doctor_id UUID REFERENCES staff_users(id) ON DELETE SET NULL,
  message TEXT NOT NULL CHECK (length(message) BETWEEN 1 AND 4000),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK ((sender_patient_id IS NOT NULL AND sender_doctor_id IS NULL) OR
         (sender_patient_id IS NULL AND sender_doctor_id IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS doctor_consultation_messages_request_idx
  ON doctor_consultation_messages (care_request_id, created_at, id);

CREATE TABLE IF NOT EXISTS patient_order_items (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  order_id UUID NOT NULL REFERENCES patient_orders(id) ON DELETE CASCADE,
  product_id UUID REFERENCES products(id) ON DELETE SET NULL,
  product_name VARCHAR(120) NOT NULL,
  quantity INTEGER NOT NULL CHECK (quantity > 0),
  unit_price_bif NUMERIC(12, 0) NOT NULL CHECK (unit_price_bif >= 0)
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  staff_user_id UUID REFERENCES staff_users(id) ON DELETE SET NULL,
  action VARCHAR(40) NOT NULL,
  product_id UUID,
  details JSONB NOT NULL DEFAULT '{}'::JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS audit_logs_created_at_idx ON audit_logs (created_at DESC);

CREATE TABLE IF NOT EXISTS staff_invitations (
  id UUID PRIMARY KEY,
  email TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin', 'pharmacist', 'doctor')),
  token_hash TEXT NOT NULL UNIQUE,
  invited_by UUID REFERENCES staff_users(id) ON DELETE SET NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  accepted_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS staff_invitations_pending_idx
  ON staff_invitations (created_at DESC) WHERE accepted_at IS NULL;
ALTER TABLE staff_invitations DROP CONSTRAINT IF EXISTS staff_invitations_role_check;
ALTER TABLE staff_invitations ADD CONSTRAINT staff_invitations_role_check
  CHECK (role IN ('admin', 'pharmacist', 'doctor'));

CREATE TABLE IF NOT EXISTS news_articles (
  id UUID PRIMARY KEY,
  title VARCHAR(180) NOT NULL,
  summary VARCHAR(500) NOT NULL,
  body TEXT NOT NULL,
  video_url TEXT,
  image_url TEXT,
  category VARCHAR(60) NOT NULL DEFAULT 'Ubuzima',
  status TEXT NOT NULL DEFAULT 'published'
    CHECK (status IN ('draft', 'pending_review', 'scheduled', 'published', 'archived')),
  scheduled_at TIMESTAMPTZ,
  views_count INTEGER NOT NULL DEFAULT 0 CHECK (views_count >= 0),
  author_id UUID REFERENCES staff_users(id) ON DELETE SET NULL,
  published_at TIMESTAMPTZ DEFAULT NOW(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK ((status = 'scheduled' AND scheduled_at IS NOT NULL) OR status <> 'scheduled')
);

ALTER TABLE news_articles ADD COLUMN IF NOT EXISTS category VARCHAR(60) NOT NULL DEFAULT 'Ubuzima';
ALTER TABLE news_articles ADD COLUMN IF NOT EXISTS image_url TEXT;
ALTER TABLE news_articles ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'published';
ALTER TABLE news_articles ADD COLUMN IF NOT EXISTS scheduled_at TIMESTAMPTZ;
ALTER TABLE news_articles ADD COLUMN IF NOT EXISTS views_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE news_articles ALTER COLUMN published_at DROP NOT NULL;
ALTER TABLE news_articles DROP CONSTRAINT IF EXISTS news_articles_status_check;
ALTER TABLE news_articles ADD CONSTRAINT news_articles_status_check
  CHECK (status IN ('draft', 'pending_review', 'scheduled', 'published', 'archived'));
ALTER TABLE news_articles DROP CONSTRAINT IF EXISTS news_articles_check;
ALTER TABLE news_articles DROP CONSTRAINT IF EXISTS news_articles_schedule_check;
ALTER TABLE news_articles ADD CONSTRAINT news_articles_schedule_check
  CHECK ((status = 'scheduled' AND scheduled_at IS NOT NULL) OR status <> 'scheduled');

CREATE INDEX IF NOT EXISTS news_articles_published_idx ON news_articles (published_at DESC)
  WHERE status = 'published';
CREATE INDEX IF NOT EXISTS news_articles_schedule_idx ON news_articles (scheduled_at)
  WHERE status = 'scheduled';

CREATE TABLE IF NOT EXISTS videos (
  id UUID PRIMARY KEY,
  title VARCHAR(180) NOT NULL,
  description VARCHAR(1000) NOT NULL,
  category VARCHAR(60) NOT NULL,
  source_type TEXT NOT NULL CHECK (source_type IN ('upload', 'youtube', 'vimeo')),
  video_url TEXT NOT NULL,
  thumbnail_url TEXT,
  status TEXT NOT NULL DEFAULT 'draft'
    CHECK (status IN ('draft', 'scheduled', 'published', 'archived')),
  scheduled_at TIMESTAMPTZ,
  published_at TIMESTAMPTZ,
  views_count INTEGER NOT NULL DEFAULT 0 CHECK (views_count >= 0),
  author_id UUID REFERENCES staff_users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK ((status = 'scheduled' AND scheduled_at IS NOT NULL) OR status <> 'scheduled')
);

CREATE INDEX IF NOT EXISTS videos_published_idx ON videos (published_at DESC)
  WHERE status = 'published';
CREATE INDEX IF NOT EXISTS videos_schedule_idx ON videos (scheduled_at)
  WHERE status = 'scheduled';

CREATE TABLE IF NOT EXISTS newsletter_subscriptions (
  id UUID PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  is_verified BOOLEAN NOT NULL DEFAULT FALSE,
  is_subscribed BOOLEAN NOT NULL DEFAULT TRUE,
  verification_token_hash TEXT,
  unsubscribe_token_hash TEXT,
  verified_at TIMESTAMPTZ,
  unsubscribed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS newsletter_active_subscribers_idx
  ON newsletter_subscriptions (id) WHERE is_verified = TRUE AND is_subscribed = TRUE;

CREATE TABLE IF NOT EXISTS newsletter_unsubscribe_tokens (
  token_hash TEXT PRIMARY KEY,
  subscription_id UUID NOT NULL REFERENCES newsletter_subscriptions(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS news_email_deliveries (
  article_id UUID NOT NULL REFERENCES news_articles(id) ON DELETE CASCADE,
  subscription_id UUID NOT NULL REFERENCES newsletter_subscriptions(id) ON DELETE CASCADE,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'sent', 'failed')),
  error_message TEXT,
  sent_at TIMESTAMPTZ,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (article_id, subscription_id)
);
