-- WARNING: This schema is for context only and is not meant to be run.
-- Table order and constraints may not be valid for execution.

CREATE TABLE public.ai_risk_scores (
  id uuid NOT NULL DEFAULT uuid_generate_v4(),
  alert_id uuid NOT NULL,
  predicted_risk numeric,
  threat_category text,
  model_version text,
  created_at timestamp without time zone DEFAULT now(),
  CONSTRAINT ai_risk_scores_pkey PRIMARY KEY (id),
  CONSTRAINT ai_risk_scores_alert_fkey FOREIGN KEY (alert_id) REFERENCES public.alerts(id)
);
CREATE TABLE public.alert_comments (
  id uuid NOT NULL DEFAULT uuid_generate_v4(),
  alert_id uuid NOT NULL,
  user_id uuid NOT NULL,
  comment text NOT NULL,
  created_at timestamp without time zone DEFAULT now(),
  CONSTRAINT alert_comments_pkey PRIMARY KEY (id),
  CONSTRAINT alert_comments_alert_fkey FOREIGN KEY (alert_id) REFERENCES public.alerts(id),
  CONSTRAINT alert_comments_user_fkey FOREIGN KEY (user_id) REFERENCES public.users(id)
);
CREATE TABLE public.alerts (
  id uuid NOT NULL DEFAULT uuid_generate_v4(),
  title text NOT NULL,
  description text,
  source_tool text,
  severity text CHECK (severity = ANY (ARRAY['LOW'::text, 'MEDIUM'::text, 'HIGH'::text, 'CRITICAL'::text])),
  status text DEFAULT 'OPEN'::text CHECK (status = ANY (ARRAY['OPEN'::text, 'IN_PROGRESS'::text, 'RESOLVED'::text])),
  risk_score numeric,
  asset_id uuid,
  assigned_to uuid,
  created_at timestamp without time zone DEFAULT now(),
  model_used text,
  severity_pred text,
  severity_final text,
  confidence numeric,
  hybrid_override boolean DEFAULT false,
  needs_review boolean DEFAULT false,
  attack_category text,
  attack_confidence numeric,
  rule_level integer,
  rule_id text,
  rule_description text,
  agent_name text,
  agent_id text,
  agent_ip text,
  source_ip text,
  event_timestamp text,
  decoder_name text,
  firedtimes integer,
  external_alert_id text,
  mitre_tactic jsonb,
  mitre_technique jsonb,
  mitre_id jsonb,
  soc_level_tier text CHECK ((soc_level_tier = ANY (ARRAY['L1'::text, 'L2'::text, 'L3'::text])) OR soc_level_tier IS NULL),
  soc_level_label text,
  soc_level_range text,
  soc_level_band text,
  soc_level_description text,
  soc_immediate_action boolean DEFAULT false,
  CONSTRAINT alerts_pkey PRIMARY KEY (id),
  CONSTRAINT alerts_asset_fkey FOREIGN KEY (asset_id) REFERENCES public.assets(id),
  CONSTRAINT alerts_user_fkey FOREIGN KEY (assigned_to) REFERENCES public.users(id)
);
CREATE TABLE public.assets (
  id uuid NOT NULL DEFAULT uuid_generate_v4(),
  hostname text NOT NULL,
  ip_address text,
  operating_system text,
  owner text,
  created_at timestamp without time zone DEFAULT now(),
  CONSTRAINT assets_pkey PRIMARY KEY (id)
);
CREATE TABLE public.low_confidence_items (
  id uuid NOT NULL DEFAULT uuid_generate_v4(),
  alert_id text,
  model_used text,
  severity_pred text,
  severity_final text,
  confidence numeric,
  needs_review boolean DEFAULT true,
  attack_category text,
  attack_confidence numeric,
  rule_level integer,
  rule_id text,
  rule_description text,
  agent_name text,
  agent_id text,
  agent_ip text,
  source_ip text,
  event_timestamp text,
  decoder_name text,
  firedtimes integer,
  mitre_tactic jsonb,
  mitre_technique jsonb,
  mitre_id jsonb,
  soc_level_tier text,
  soc_level_label text,
  soc_level_range text,
  soc_level_band text,
  soc_level_description text,
  soc_immediate_action boolean DEFAULT false,
  created_at timestamp without time zone DEFAULT now(),
  CONSTRAINT low_confidence_items_pkey PRIMARY KEY (id)
);
CREATE TABLE public.reports (
  id uuid NOT NULL DEFAULT uuid_generate_v4(),
  generated_by uuid,
  report_type text,
  content text,
  created_at timestamp without time zone DEFAULT now(),
  CONSTRAINT reports_pkey PRIMARY KEY (id),
  CONSTRAINT reports_user_fkey FOREIGN KEY (generated_by) REFERENCES public.users(id)
);
CREATE TABLE public.users (
  id uuid NOT NULL DEFAULT uuid_generate_v4(),
  name text NOT NULL,
  email text NOT NULL UNIQUE,
  password text NOT NULL,
  role text NOT NULL CHECK (role = ANY (ARRAY['SOC_ANALYST'::text, 'VULN_ANALYST'::text, 'SOC_MANAGER'::text])),
  created_at timestamp without time zone DEFAULT now(),
  is_active boolean NOT NULL DEFAULT true,
  CONSTRAINT users_pkey PRIMARY KEY (id)
);
CREATE TABLE public.vulnerabilities (
  id uuid NOT NULL DEFAULT uuid_generate_v4(),
  cve_id text,
  description text,
  cvss_score numeric,
  exploitability_score numeric,
  asset_id uuid,
  priority_level text CHECK (priority_level = ANY (ARRAY['LOW'::text, 'MEDIUM'::text, 'HIGH'::text, 'CRITICAL'::text])),
  remediation_status text DEFAULT 'OPEN'::text CHECK (remediation_status = ANY (ARRAY['OPEN'::text, 'IN_PROGRESS'::text, 'FIXED'::text])),
  discovered_at timestamp without time zone DEFAULT now(),
  priority text,
  needs_review boolean DEFAULT false,
  CONSTRAINT vulnerabilities_pkey PRIMARY KEY (id),
  CONSTRAINT vulnerabilities_asset_fkey FOREIGN KEY (asset_id) REFERENCES public.assets(id)
);

-- Human-in-the-loop feedback table for safe batch retraining.
CREATE TABLE public.feedback (
  id bigserial PRIMARY KEY,
  alert_id uuid NOT NULL,
  ml_prediction text NOT NULL,
  correct_label text,
  is_wrong boolean NOT NULL DEFAULT false,
  analyst_id uuid,
  model_name text NOT NULL DEFAULT 'attack_category',
  created_at timestamp without time zone DEFAULT now(),
  CONSTRAINT feedback_user_fkey FOREIGN KEY (analyst_id) REFERENCES public.users(id)
);

CREATE INDEX feedback_model_created_idx ON public.feedback(model_name, created_at DESC);
CREATE INDEX feedback_alert_idx ON public.feedback(alert_id);

-- Model version registry for promotion/rollback operations.
CREATE TABLE public.model_versions (
  id uuid NOT NULL DEFAULT uuid_generate_v4(),
  model_name text NOT NULL,
  version integer NOT NULL,
  filename text,
  accuracy numeric,
  precision numeric,
  training_date timestamp without time zone DEFAULT now(),
  dataset_size integer,
  is_active boolean NOT NULL DEFAULT false,
  metadata jsonb,
  created_by text,
  created_at timestamp without time zone DEFAULT now(),
  CONSTRAINT model_versions_pkey PRIMARY KEY (id)
);

CREATE UNIQUE INDEX model_versions_unique_idx ON public.model_versions(model_name, version);
CREATE INDEX model_versions_active_idx ON public.model_versions(model_name, is_active);

-- SOC auditability for feedback and model lifecycle events.
CREATE TABLE public.audit_logs (
  id uuid NOT NULL DEFAULT uuid_generate_v4(),
  event_type text NOT NULL,
  actor_id text,
  details jsonb,
  created_at timestamp without time zone DEFAULT now(),
  CONSTRAINT audit_logs_pkey PRIMARY KEY (id)
);

CREATE INDEX audit_logs_event_created_idx ON public.audit_logs(event_type, created_at DESC);