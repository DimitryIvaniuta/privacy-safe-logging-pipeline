\
package com.github.dimitryivaniuta.gateway.logging;

import java.util.Locale;
import java.util.concurrent.atomic.LongAdder;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * PII redaction utility.
 *
 * <p>Redacts emails, phones and card numbers (with Luhn validation).</p>
 */
public final class Redactor {

    private Redactor() {}

    private static final LongAdder EMAIL_REDACTIONS = new LongAdder();
private static final LongAdder PHONE_REDACTIONS = new LongAdder();
private static final LongAdder CARD_REDACTIONS = new LongAdder();

/** @return total number of email redactions performed since JVM start */
public static long emailRedactions() { return EMAIL_REDACTIONS.sum(); }

/** @return total number of phone redactions performed since JVM start */
public static long phoneRedactions() { return PHONE_REDACTIONS.sum(); }

/** @return total number of card redactions performed since JVM start */
public static long cardRedactions() { return CARD_REDACTIONS.sum(); }

    private static final Pattern EMAIL = Pattern.compile(
            "(?i)([a-z0-9._%+-]{1,64})@([a-z0-9.-]{1,253}\\.[a-z]{2,24})"
    );

    private static final Pattern PHONE = Pattern.compile(
            "(?x)(?<!\\d)(\\+?\\d{1,3}[\\s.-]?)?(\\(?\\d{2,4}\\)?[\\s.-]?)?\\d{3}[\\s.-]?\\d{2,3}[\\s.-]?\\d{2,3}(?!\\d)"
    );

    private static final Pattern CARD_CANDIDATE = Pattern.compile(
            "(?<!\\d)(?:\\d[ -]?){13,19}(?!\\d)"
    );

    /**
     * Redacts PII in input.
     *
     * @param input text (nullable)
     * @return redacted string (non-null)
     */
    public static String redact(String input) {
        if (input == null || input.isBlank()) {
            return "";
        }

        String out = input;

        if (EMAIL.matcher(out).find()) {
            out = redactEmail(out);
        }
        if (PHONE.matcher(out).find()) {
            out = redactPhone(out);
        }
        if (CARD_CANDIDATE.matcher(out).find()) {
            out = redactCard(out);
        }
        return out;
    }

    private static String redactEmail(String s) {
        Matcher m = EMAIL.matcher(s);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            String local = m.group(1);
            String domain = m.group(2);
            String maskedLocal = local.length() <= 2 ? "***" : local.substring(0, 1) + "***" + local.substring(local.length() - 1);
            String replacement = maskedLocal + "@" + domain.toLowerCase(Locale.ROOT);
            EMAIL_REDACTIONS.increment();
            PHONE_REDACTIONS.increment();
            m.appendReplacement(sb, Matcher.quoteReplacement(replacement));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    private static String redactPhone(String s) {
        Matcher m = PHONE.matcher(s);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            String raw = m.group();
            String digits = raw.replaceAll("\\D", "");
            if (digits.length() < 7) {
                m.appendReplacement(sb, Matcher.quoteReplacement(raw));
                continue;
            }
            String suffix = digits.length() <= 4 ? digits : digits.substring(digits.length() - 4);
            String replacement = "***PHONE***" + suffix;
            m.appendReplacement(sb, Matcher.quoteReplacement(replacement));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    private static String redactCard(String s) {
        Matcher m = CARD_CANDIDATE.matcher(s);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            String raw = m.group();
            String digits = raw.replaceAll("\\D", "");
            if (digits.length() < 13 || digits.length() > 19 || !luhnValid(digits)) {
                m.appendReplacement(sb, Matcher.quoteReplacement(raw));
                continue;
            }
            String last4 = digits.substring(digits.length() - 4);
            String replacement = "**** **** **** " + last4;
            CARD_REDACTIONS.increment();
            m.appendReplacement(sb, Matcher.quoteReplacement(replacement));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    static boolean luhnValid(String digits) {
        int sum = 0;
        boolean alternate = false;
        for (int i = digits.length() - 1; i >= 0; i--) {
            int n = digits.charAt(i) - '0';
            if (alternate) {
                n *= 2;
                if (n > 9) n -= 9;
            }
            sum += n;
            alternate = !alternate;
        }
        return sum % 10 == 0;
    }
}
