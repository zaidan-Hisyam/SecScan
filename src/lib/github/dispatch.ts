/**
 * Modul untuk memicu GitHub Actions Workflow via workflow_dispatch API.
 * Memerlukan GitHub Personal Access Token (PAT) atau GitHub App Token dengan izin `actions:write`.
 */

export interface TriggerWorkflowParams {
  scanId: string;
  hostname: string;
}

export async function triggerGitHubScanWorkflow(params: TriggerWorkflowParams): Promise<{
  success: boolean;
  error?: string;
  simulated?: boolean;
}> {
  const token = process.env.GITHUB_TOKEN;
  const owner = process.env.GITHUB_REPO_OWNER;
  const repo = process.env.GITHUB_REPO_NAME;
  const workflowFile = process.env.GITHUB_WORKFLOW_FILE || "security-scan.yml";
  const ref = process.env.GITHUB_BRANCH_REF || "main";

  // Jika kredensial GitHub belum diisi di lingkungan lokal, berikan warning/fallback yang jelas
  if (!token || !owner || !repo) {
    console.warn(
      "[GitHub Dispatch] GITHUB_TOKEN, GITHUB_REPO_OWNER, atau GITHUB_REPO_NAME belum diatur di .env.local."
    );
    return {
      success: false,
      error:
        "Kredensial GitHub Actions belum diatur di server (GITHUB_TOKEN, GITHUB_REPO_OWNER, GITHUB_REPO_NAME).",
    };
  }

  const url = `https://api.github.com/repos/${owner}/${repo}/actions/workflows/${workflowFile}/dispatches`;

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);

    const res = await fetch(url, {
      method: "POST",
      signal: controller.signal,
      headers: {
        Accept: "application/vnd.github.v3+json",
        Authorization: `Bearer ${token}`,
        "User-Agent": "SecScan-Portal/1.0",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        ref: ref,
        inputs: {
          scan_id: params.scanId,
          hostname: params.hostname,
        },
      }),
    });

    clearTimeout(timeoutId);

    if (res.status === 204) {
      return { success: true };
    }

    const resData = await res.text();
    return {
      success: false,
      error: `GitHub API mengembalikan status ${res.status}: ${resData}`,
    };
  } catch (err: unknown) {
    if (err instanceof Error && err.name === "AbortError") {
      return { success: false, error: "Timeout saat menghubungi GitHub Actions API" };
    }
    return {
      success: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}
