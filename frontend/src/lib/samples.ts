import type { ScanType } from "../types";

/**
 * Illustrative inputs used by the “load an example” action.
 * They are only pre-filled text — every verdict still comes from the live engine.
 */
export const SAMPLES: Record<ScanType, string> = {
  message: `URGENT: Your account has been temporarily suspended due to unauthorized access.
Dear customer, you must verify your identity within 24 hours or your access will be permanently closed.
Confirm your password and card number here: http://secure-paypa1-verify.account-check.top/login
Do not ignore this final notice.`,

  email: `From: PayPal Security Team <service@paypa1-alerts.co>
Reply-To: recovery.desk@mail.ru
Subject: Final notice — unusual sign-in detected

Dear valued customer,

We detected a suspicious login attempt on your account. For your protection, your account will be limited within 24 hours unless you confirm your details.

Please review the attached invoice and sign in here to restore access:
http://198.51.100.23/paypal/secure/login-verify?session=9f21

Failure to respond will result in permanent suspension.

PayPal Account Services`,

  url: "http://appleid.apple.com-verify-account.secure-login.xyz/signin?ref=restore",
};

export const PLACEHOLDERS: Record<ScanType, string> = {
  message: "Paste the SMS, chat or direct message you received…",
  email: "Paste the full email, including the From, Reply-To and Subject lines if you have them…",
  url: "https://example.com/login",
};
