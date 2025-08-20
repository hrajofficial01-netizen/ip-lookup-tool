--
-- PostgreSQL database dump
--

-- Dumped from database version 17.5 (Debian 17.5-1.pgdg120+1)
-- Dumped by pg_dump version 17.5

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: lookup_data; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.lookup_data (
    entry text NOT NULL,
    entry_type text NOT NULL,
    isp text,
    asn text,
    country text,
    detection_count integer DEFAULT 0 NOT NULL,
    threat_actor text,
    country_origin jsonb,
    threat_category jsonb,
    campaign_name text,
    target_sector jsonb,
    malware_families text,
    associated_ip text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: search_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.search_log (
    entry character varying NOT NULL,
    client_name character varying NOT NULL,
    first_searched timestamp without time zone DEFAULT now() NOT NULL,
    last_searched timestamp without time zone DEFAULT now() NOT NULL,
    lookup_count integer NOT NULL
);


--
-- Name: lookup_data lookup_data_new_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lookup_data
    ADD CONSTRAINT lookup_data_new_pkey PRIMARY KEY (entry);


--
-- Name: search_log pk_search_log; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.search_log
    ADD CONSTRAINT pk_search_log PRIMARY KEY (entry, client_name);


--
-- PostgreSQL database dump complete
--
--
-- Name: search_log_new; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.search_log_new (
    id serial PRIMARY KEY,
    entry character varying NOT NULL,
    entry_type character varying,
    client_name character varying NOT NULL,
    searched_at timestamp with time zone DEFAULT now() NOT NULL
);

-- Optional: add indexes for performance

CREATE INDEX idx_search_log_new_entry ON public.search_log_new (entry);
CREATE INDEX idx_search_log_new_entry_type ON public.search_log_new (entry_type);
CREATE INDEX idx_search_log_new_client_name ON public.search_log_new (client_name);
CREATE INDEX idx_search_log_new_searched_at ON public.search_log_new (searched_at);

