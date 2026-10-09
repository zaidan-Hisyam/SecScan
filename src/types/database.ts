export type Json =
  | string
  | number
  | boolean
  | null
  | { [key: string]: Json | undefined }
  | Json[];

export type SeverityLevel = "info" | "low" | "medium" | "high" | "critical";
export type ScanStatus = "queued" | "running" | "done" | "failed";

export interface Database {
  public: {
    Tables: {
      profiles: {
        Row: {
          id: string;
          email: string;
          created_at: string;
        };
        Insert: {
          id: string;
          email: string;
          created_at?: string;
        };
        Update: {
          id?: string;
          email?: string;
          created_at?: string;
        };
      };
      domains: {
        Row: {
          id: string;
          owner_id: string;
          hostname: string;
          verify_token: string;
          verified: boolean;
          verified_at: string | null;
          created_at: string;
        };
        Insert: {
          id?: string;
          owner_id: string;
          hostname: string;
          verify_token: string;
          verified?: boolean;
          verified_at?: string | null;
          created_at?: string;
        };
        Update: {
          id?: string;
          owner_id?: string;
          hostname?: string;
          verify_token?: string;
          verified?: boolean;
          verified_at?: string | null;
          created_at?: string;
        };
      };
      scans: {
        Row: {
          id: string;
          domain_id: string;
          status: ScanStatus;
          started_at: string | null;
          finished_at: string | null;
          summary: Json;
          triggered_by: string | null;
          created_at: string;
        };
        Insert: {
          id?: string;
          domain_id: string;
          status?: ScanStatus;
          started_at?: string | null;
          finished_at?: string | null;
          summary?: Json;
          triggered_by?: string | null;
          created_at?: string;
        };
        Update: {
          id?: string;
          domain_id?: string;
          status?: ScanStatus;
          started_at?: string | null;
          finished_at?: string | null;
          summary?: Json;
          triggered_by?: string | null;
          created_at?: string;
        };
      };
      findings: {
        Row: {
          id: string;
          scan_id: string;
          tool: string;
          rule_id: string;
          title: string;
          severity: SeverityLevel;
          description: string;
          evidence: string | null;
          remediation: string;
          created_at: string;
        };
        Insert: {
          id?: string;
          scan_id: string;
          tool: string;
          rule_id: string;
          title: string;
          severity: SeverityLevel;
          description: string;
          evidence?: string | null;
          remediation: string;
          created_at?: string;
        };
        Update: {
          id?: string;
          scan_id?: string;
          tool?: string;
          rule_id?: string;
          title?: string;
          severity?: SeverityLevel;
          description?: string;
          evidence?: string | null;
          remediation?: string;
          created_at?: string;
        };
      };
    };
  };
}
