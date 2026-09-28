// securityEngine.js
const db = require('./db');

const FAILED_LOGIN_THRESHOLD = 3;
const MASS_RETRIEVAL_THRESHOLD = 20;

/**
 * Creates a security alert record in the database
 */
async function createAlert(ruleName, severity, userId, userRole, evidenceDetails) {
    try {
        await db.query(
            `INSERT INTO security_alerts (rule_name, severity, user_id, user_role, evidence_details, status) 
             VALUES (?, ?, ?, ?, ?, 'OPEN')`,
            [ruleName, severity, userId || 0, userRole || 'Guest', evidenceDetails]
        );
        console.log(`🚨 [SECURITY ALERT CREATED] ${ruleName} (${severity}): ${evidenceDetails}`);
    } catch (err) {
        console.error("Error creating security alert:", err.message);
    }
}

/**
 * Evaluates audit log entries against security threat patterns
 */
async function evaluateSecurityRules(logEntry) {
    const { userId, userRole, action, status, recordsCount, isEmergencyOverride } = logEntry;

    // PATTERN 1: Repeated Failed Logins (Within 5 minutes)
    if (action.includes('/login') && status === 'DENIED') {
        try {
            const [rows] = await db.query(
                `SELECT COUNT(*) as count FROM access_logs 
                 WHERE action LIKE '%/login%' AND status = 'DENIED'
                 AND timestamp >= NOW() - INTERVAL 5 MINUTE`
            );

            const failureCount = rows[0]?.count || 0;

            if (failureCount >= FAILED_LOGIN_THRESHOLD) {
                await createAlert(
                    'REPEATED_FAILED_LOGINS',
                    'HIGH',
                    userId,
                    userRole,
                    `Multiple failed login attempts detected (${failureCount} failures in the last 5 minutes).`
                );
            }
        } catch (err) {
            console.error("Rule Evaluation Error (Failed Logins):", err.message);
        }
    }

    // PATTERN 2: Mass Record Retrieval / Data Leak Risk
    if (recordsCount >= MASS_RETRIEVAL_THRESHOLD) {
        if (userRole === 'Doctor' && isEmergencyOverride) {
            console.log(`[SECURITY NOTICE] Rapid access by Doctor ID ${userId} verified as legitimate ER Emergency Burst.`);
            return;
        }

        await createAlert(
            'MASS_RECORD_RETRIEVAL',
            'CRITICAL',
            userId,
            userRole,
            `User requested an unusually high number of records (${recordsCount} records) at endpoint ${action}.`
        );
    }

    // PATTERN 3: Unauthorized Access Attempt
    if (status === 'DENIED' && !action.includes('/login')) {
        await createAlert(
            'UNAUTHORIZED_SCOPE_ACCESS',
            'MEDIUM',
            userId,
            userRole,
            `Unauthorized access attempt denied for endpoint: ${action}.`
        );
    }
}

module.exports = { evaluateSecurityRules, createAlert };