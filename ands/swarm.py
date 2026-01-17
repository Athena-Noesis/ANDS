import math
from typing import List, Dict
from .models import ScanReport

class SwarmScorer:
    """Calculates emergent ANDS scores for multi-agent systems."""

    @staticmethod
    def calculate_composite(reports: List[Dict]) -> str:
        """
        Formula for Composite ANDS:
        C (Cognition): Logarithmic scaling of collective Cognition.
        A (Authority): Maximum Authority in the swarm (the 'weakest link').
        M (Memory): Sum of shared memory, max of private memory.
        G (Governance): Minimum Governance (swarm is only as safe as its least governed agent).
        R (Risk): Cumulative Risk based on total capabilities.
        S (Sustainability): Sum of resource intensity.
        """
        if not reports:
            return "0.0.0.0.0.0"

        c_sum = 0
        a_max = 0
        m_max = 0
        g_min = 5
        r_max = 0
        s_sum = 0
        has_s = False

        for r in reports:
            code = r.get("inferred_ands", "0.0.0.0.0")
            parts = [int(p) for p in code.split('.')]
            if len(parts) >= 6:
                has_s = True

            # Pad to 6 for internal calculation
            if len(parts) < 6: parts += [0] * (6 - len(parts))

            c_sum += parts[0]
            a_max = max(a_max, parts[1])
            m_max = max(m_max, parts[2])
            g_min = min(g_min, parts[3])
            r_max = max(r_max, parts[4])
            s_sum += parts[5]

        # Logarithmic cognition scaling: log2(total_cognition) + baseline
        c_composite = min(5, round(math.log2(c_sum + 1)))
        a_composite = a_max
        m_composite = m_max
        g_composite = g_min
        r_composite = r_max

        result = f"{c_composite}.{a_composite}.{m_composite}.{g_composite}.{r_composite}"
        if has_s:
            s_composite = min(5, s_sum)
            result += f".{s_composite}"

        return result
