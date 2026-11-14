import { SamplePreset } from '../types';

export const SAMPLE_PRESETS: SamplePreset[] = [
  {
    id: 'kyc-sms',
    label: 'KYC SMS',
    shortHint: 'Lookalike SBI domain + urgent PAN block threat',
    content:
      'Dear Customer, Your SBI YONO account has been blocked today because your PAN card is expired. Update your KYC immediately at https://yonosbi-kyc-verify.top/login within 24 hours to avoid permanent suspension.',
  },
  {
    id: 'upi-collect',
    label: 'UPI collect request',
    shortHint: 'PIN-to-receive deception + impersonated VPA',
    content:
      'Cashback Alert: ₹2,500 electricity subsidy credited from State Desk via refund.sbi@ybl. Approve the collect request and enter your 4-digit UPI PIN to receive money in your bank account immediately.',
  },
  {
    id: 'fake-job',
    label: 'Fake job offer',
    shortHint: 'High daily payout + Telegram prepaid task fee',
    content:
      'Part-time WFH opportunity! Earn ₹3,500 to ₹8,000 per day simply by liking YouTube videos. Complete your VIP Telegram prepaid task and pay a refundable registration fee of Rs 1,000 to release your daily payout: https://bit.ly/wfh-payout-in',
  },
  {
    id: 'safe-message',
    label: 'Safe message',
    shortHint: 'Legitimate bank OTP alert with defensive warning',
    content:
      '482910 is your OTP for transaction of INR 1,450.00 at Amazon on your SBI Debit Card ending 4012. Valid for 10 mins. Do NOT share this OTP with anyone. Bank never asks for OTP or UPI PIN.',
  },
];
