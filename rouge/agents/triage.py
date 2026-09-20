import json
from ..client import get_client

TRIAGE_SYSTEM = """You are a vulnerability triage specialist (The Triage Agent). Your job is to review confirmed vulnerabilities and determine which one is the most critical to fix first.

Given a list of confirmed vulnerabilities, rank them by severity considering:
1. Exploitability - How easy is it to exploit?
2. Impact - What's the worst that could happen if exploited?
3. Exposure - Is the vulnerable endpoint exposed to untrusted users?

Return ONLY a JSON object with this structure:
{
  "ranked_vulnerabilities": [
    {
      "index": <original array index>,
      "reasoning": "<why this rank>",
      "recommended_fix_priority": "<critical|high|medium>"
    }
  ],
  "top_priority_index": <index of the most critical vuln>
}

Return ONLY the JSON object, no other text."""


async def triage_prioritize(
    confirmed: list[dict],
    client=None,
) -> tuple[list[dict], dict | None]:
    if client is None:
        client = get_client()
    if not confirmed:
        return [], None

    vulns_for_llm = []
    for i, v in enumerate(confirmed):
        vulns_for_llm.append({
            "index": i,
            "type": v["type"],
            "function": v["function"],
            "file": v["file"],
            "line": v["line"],
            "description": v["description"],
            "exploit_output": v.get("exploit_output", "")[:500],
        })

    user_msg = f"""Confirmed vulnerabilities:

```json
{json.dumps(vulns_for_llm, indent=2)}
```

Rank these by severity and pick the top priority issue to fix."""

    try:
        response = await client.generate(
            system_prompt=TRIAGE_SYSTEM,
            user_message=user_msg,
            max_tokens=1024,
            temperature=0.1,
        )
        response = response.strip()
        if response.startswith("```"):
            response = response.split("```")[1]
            if response.startswith("json"):
                response = response[4:]
            response = response.strip()

        triage_result = json.loads(response)
        top_idx = triage_result.get("top_priority_index", 0)

        # The model returns a ranking as [{index, ...}]; convert to a
        # position map so the sort actually follows it. Unknown indices sink.
        ranked = triage_result.get("ranked_vulnerabilities", [])
        position = {}
        for pos, entry in enumerate(ranked):
            if isinstance(entry, dict) and isinstance(entry.get("index"), int):
                position.setdefault(entry["index"], pos)

        sorted_vulns = sorted(
            enumerate(confirmed),
            key=lambda pair: (position.get(pair[0], len(confirmed)), pair[0]),
        )
        sorted_vulns = [v for _, v in sorted_vulns]
        for i, v in enumerate(confirmed):
            v["triage_rank"] = position.get(i, len(confirmed))
            for entry in ranked:
                if isinstance(entry, dict) and entry.get("index") == i:
                    v["triage_reasoning"] = str(entry.get("reasoning", ""))[:300]
                    break

        if not isinstance(top_idx, int) or not (0 <= top_idx < len(confirmed)):
            top_idx = 0
        return sorted_vulns, sorted_vulns[0] if sorted_vulns else None

    except (json.JSONDecodeError, Exception):
        sorted_by_severity = sorted(
            confirmed,
            key=lambda v: {"critical": 0, "high": 1, "medium": 2}.get(v.get("severity", "medium"), 3),
        )
        return sorted_by_severity, sorted_by_severity[0]
