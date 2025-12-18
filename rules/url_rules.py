def rule_based_url_detection(features):
    risk_score = 0

    if features["url_length"] > 75:
        risk_score += 1

    if features["has_ip"] == 1:
        risk_score += 1

    if features["has_at"] == 1:
        risk_score += 1

    if features["subdomain_count"] > 2:
        risk_score += 1

    if features["has_https"] == 0:
        risk_score += 1

    return risk_score >= 2
