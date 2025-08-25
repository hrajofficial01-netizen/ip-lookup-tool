--
-- PostgreSQL database dump
--

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

--
-- Name: public; Type: SCHEMA; Schema: -; Owner: iplookupdb_user
--

-- *not* creating schema, since initdb creates it

ALTER SCHEMA public OWNER TO iplookupdb_user;


-- Extensions timescaledb removed

--
-- Name: EXTENSION pg_stat_statements; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pg_stat_statements WITH SCHEMA public;

--
-- Name: EXTENSION pg_stat_statements; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION pg_stat_statements IS 'track planning and execution statistics of all SQL statements executed';

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: alembic_version; Type: TABLE; Schema: public; Owner: iplookupdb_user
--

CREATE TABLE public.alembic_version (
    version_num character varying(32) NOT NULL
);

ALTER TABLE public.alembic_version OWNER TO iplookupdb_user;

--
-- Name: lookup_data; Type: TABLE; Schema: public; Owner: iplookupdb_user
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

ALTER TABLE public.lookup_data OWNER TO iplookupdb_user;

--
-- Name: search_log; Type: TABLE; Schema: public; Owner: iplookupdb_user
--

CREATE TABLE public.search_log (
    entry character varying NOT NULL,
    entry_type character varying,
    client_name character varying NOT NULL,
    first_searched timestamp without time zone DEFAULT now() NOT NULL,
    last_searched timestamp without time zone DEFAULT now() NOT NULL,
    lookup_count integer NOT NULL,
    PRIMARY KEY (entry, client_name)
);

ALTER TABLE public.search_log OWNER TO iplookupdb_user;

--
-- Name: search_log_new; Type: TABLE; Schema: public; Owner: iplookupdb_user
--

CREATE TABLE public.search_log_new (
    id integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    entry_type character varying,
    entry character varying NOT NULL,
    client_name character varying NOT NULL,
    searched_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE public.search_log_new OWNER TO iplookupdb_user;

-- other standard constraints, indexes and sequences follow here unchanged
