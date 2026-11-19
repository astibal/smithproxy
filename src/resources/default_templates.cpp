// Built-in template payloads, isolated from configuration and runtime logic.
// The sole source of shipped defaults for installation, migration and maintenance.
#include "default_templates.hpp"

namespace sx::resources::default_templates {

const std::map<std::string, std::string>& all() {
    static const std::map<std::string, std::string> templates {
        {"templates/replacement/en/html_img_warning.txt", R"sx_template(<img style="vertical-align:middle; padding: 0px 0px 3px 0px;" alt="" src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEEAAABACAMAAAByderSAAADAFBMVEUAAAAAADMAAGYAAJkAAMwAAP8AMwAAMzMAM2YAM5kAM8wAM/8AZgAAZjMAZmYAZpkAZswAZv8AmQAAmTMAmWYAmZkAmcwAmf8AzAAAzDMAzGYAzJkAzMwAzP8A/wAA/zMA/2YA/5kA/8wA//8zAAAzADMzAGYzAJkzAMwzAP8zMwAzMzMzM2YzM5kzM8wzM/8zZgAzZjMzZmYzZpkzZswzZv8zmQAzmTMzmWYzmZkzmcwzmf8zzAAzzDMzzGYzzJkzzMwzzP8z/wAz/zMz/2Yz/5kz/8wz//9mAABmADNmAGZmAJlmAMxmAP9mMwBmMzNmM2ZmM5lmM8xmM/9mZgBmZjNmZmZmZplmZsxmZv9mmQBmmTNmmWZmmZlmmcxmmf9mzABmzDNmzGZmzJlmzMxmzP9m/wBm/zNm/2Zm/5lm/8xm//+ZAACZADOZAGaZAJmZAMyZAP+ZMwCZMzOZM2aZM5mZM8yZM/+ZZgCZZjOZZmaZZpmZZsyZZv+ZmQCZmTOZmWaZmZmZmcyZmf+ZzACZzDOZzGaZzJmZzMyZzP+Z/wCZ/zOZ/2aZ/5mZ/8yZ///MAADMADPMAGbMAJnMAMzMAP/MMwDMMzPMM2bMM5nMM8zMM//MZgDMZjPMZmbMZpnMZszMZv/MmQDMmTPMmWbMmZnMmczMmf/MzADMzDPMzGbMzJnMzMzMzP/M/wDM/zPM/2bM/5nM/8zM////AAD/ADP/AGb/AJn/AMz/AP//MwD/MzP/M2b/M5n/M8z/M///ZgD/ZjP/Zmb/Zpn/Zsz/Zv//mQD/mTP/mWb/mZn/mcz/mf//zAD/zDP/zGb/zJn/zMz/zP///wD//zP//2b//5n//8z///8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABlenwdAAABAHRSTlP///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAG8mZagAAAAlwSFlzAAAOxAAADsQBlSsOGwAAAhBJREFUWIWtmD16xiAIgLn/ebK5ubm5eZ3PJMqPINincWobeQUEhEKzV62l5JyelXMptW42NvClr74CiiZ0+Vv8WtYDsRiK0OWVNFI6IyLc8lvAo4higALs5W01OKFWIZ/YEgzpDUaohe289e2Oe1cRtqUk1AAOWMS5dgIiEKABlrsWJ3MEaIApv/iZIUABnADurtaGwKRHCrz7kHDhxkGY6gWAwm4kcwJ+ycWRb62IuBiHAf8SaSADNhUkTBvSoQnjUocdQJ+OAVmcCOhgdE0AuKvEQORBOFGBfHD7irR+CPOOPRUI8J7DZZDgqSAilv/hJby/eF5QALy+2wxo8+d9NsyQZ5vqPLcTphEOwMrpimZAZIQNYGYAqeMD1qwlArnE9YFKezw5INgmSMLwiEmg6q2vaiiXXIJ1jXuCdRV7Exrlo0Pg12gpGFqxiYNzP1AcbOKdCPZtBia0MB7WeuASrKg+ADSdFzxrAic+e4igs/sEwLNbVRhRlbcAVmHWKnekgaxystIeAkSlFdV+W1BWFS5G4C/OYR+xvDjs1XPTWXsBXz0kZqtNclUYBHr9/wjA13/pTcJeCn1FHYjoj/bZOBYBWBfUeEMdmYC3JXu5wtq8s15q6Qa5HdnrSI2I/awr/qAzd6eDdcSwp4MPJpQPpiTpq83yJ7XFXZZ8OC0GapxMrO2Dqbn9f3JXlOC/Bz9qVtX2VH41RgAAAABJRU5ErkJggg=="/>)sx_template"},
        {"templates/replacement/en/html_page.txt", R"sx_template(<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{{ title }}</title>
  {{ meta }}
  <style>
    *{box-sizing:border-box}body{margin:0;padding:2rem;background:#f4f6f5;color:#17201c;font-family:system-ui,sans-serif;line-height:1.5}
    main{width:min({{ window_width }},100%);margin:auto;padding:2rem;border:1px solid #ccd5d0;background:#fff}
    .btn,.btn-red{display:inline-block;padding:.65rem 1rem;border:0;background:#187a48;color:#fff;font:inherit;font-weight:700}.btn-red{background:#b63737}
    .fg-red{color:#a72626}
  </style>
</head>
<body><main>{{ message }}</main></body>
</html>
)sx_template"},
        {"templates/replacement/en/test.txt", R"sx_template(smithproxy testing message)sx_template"},
        {"templates/replacement/en/tls_certificate_details.txt", R"sx_template(<details class="tls-details">
    <summary>More information</summary>
    <h3>Recorded verification findings</h3>
    {{ reasons }}
    <p>These are the findings recorded by the proxy. An unlisted check is not necessarily a passed check.</p>
    <h3>Original server certificate</h3>
    <dl>
        {{ fields }}
    </dl>
</details>
)sx_template"},
        {"templates/replacement/en/tls_certificate_field.txt", R"sx_template(<dt>{{ label }}</dt><dd>{{ value }}</dd>
)sx_template"},
        {"templates/replacement/en/tls_override_form.txt", R"sx_template(<form action="/SM/IT/HP/RO/XY/override/{{ token }}" method="get">
    <input type="hidden" name="orig_url" value="{{ original_target }}">
    <input type="submit" value="Override" class="btn-red">
</form>
)sx_template"},
        {"templates/replacement/en/tls_reason.txt", R"sx_template(<section class="reason{{ severity_class }}">
    <h3>Reason {{ number }}</h3>
    <p>{{ text }}</p>
</section>
)sx_template"},
        {"templates/replacement/en/tls_redirect.txt", R"sx_template(<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta http-equiv="Refresh" content="0; url={{ target }}">
    <title>Redirecting</title>
</head>
<body></body>
</html>
)sx_template"},
        {"templates/replacement/en/tls_redirect_top.txt", R"sx_template(<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Redirecting</title>
    <script>top.location.href="{{ target }}";</script>
</head>
<body></body>
</html>
)sx_template"},
        {"templates/replacement/en/tls_replacement.txt", R"sx_template(<!doctype html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width,initial-scale=1">
        <meta name="color-scheme" content="dark">
        <meta name="theme-color" content="#07110f">
        <title>
            TLS security warning
        </title>
    <style>
:root {
    --bg: #07110f;
    --bg2:#091511;
    --panel: #0c1916;
    --ink: #eef7f2;
    --muted: #93aaa0;
    --line: rgba(179,214,198,.16);
    --accent: #83f28f;
    --target: #63e6d7;
    --danger: #ff786f;
    --danger-ink: #190604;
    --danger-bg: rgba(255,120,111,.09);
    --glow: rgba(31,199,123,.13);
    --card-shadow: rgba(0,0,0,.38);
}
{% include tls_replacement_common.txt %}
)sx_template"},
        {"templates/replacement/en/tls_replacement_branded.txt", R"sx_template(<!doctype html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width,initial-scale=1">
        <meta name="color-scheme" content="dark">
        <meta name="theme-color" content="#07110f">
        <title>
            TLS security warning
        </title>
    <style>
:root {
    --bg: #07110f;
    --bg2:#091511;
    --panel: #0c1916;
    --ink: #eef7f2;
    --muted: #93aaa0;
    --line: rgba(179,214,198,.16);
    --accent: #83f28f;
    --target: #63e6d7;
    --danger: #ff786f;
    --danger-ink: #190604;
    --danger-bg: rgba(255,120,111,.09);
    --glow: rgba(31,199,123,.13);
    --card-shadow: rgba(0,0,0,.38);
}
{% include tls_replacement_common.txt %}
)sx_template"},
        {"templates/replacement/en/tls_replacement_common.txt", R"sx_template(* {
    box-sizing: border-box;
}

html {
    min-height: 100%;
    background: var(--bg);
}

body {
    min-height: 100vh;
    margin: 0;
    padding: clamp(1.25rem,5vw,4.5rem) 1.25rem;
    background: radial-gradient(circle at 12% 5%,var(--glow),transparent 34rem),linear-gradient(145deg,var(--bg),var(--bg2) 60%,var(--bg));
    color: var(--ink);
    font-family: Inter,Manrope,"Segoe UI",system-ui,sans-serif;
    line-height: 1.55;
}

.windowlet {
    width: min(760px,100%);
    margin: 0 auto;
}

.brand {
    display: flex;
    align-items: center;
    gap: .7rem;
    margin: 0 0 1.25rem .25rem;
    color: var(--ink);
    font-size: 1.05rem;
    font-weight: 800;
    letter-spacing: -.03em;
}

.brand img {
    display: block;
    width: 3rem;
    height: 3rem;
}

.brand span {
    display: block;
}

.brand small {
    display: block;
    margin-top: -.16rem;
    color: var(--muted);
    font: 400 .64rem ui-monospace,SFMono-Regular,Consolas,monospace;
    letter-spacing: .02em;
}

.windowlet-screen {
    overflow: hidden;
    border: 1px solid var(--line);
    background: linear-gradient(145deg,color-mix(in srgb,var(--ink) 2.5%,transparent),transparent),var(--panel);
    box-shadow: 0 2rem 6rem var(--card-shadow);
}

.windowlet-screen:before {
    display: block;
    height: .22rem;
    background: linear-gradient(90deg,var(--danger),#e8b763 48%,var(--accent));
    content: "";
}

.message {
    padding: clamp(1.5rem,5vw,3.25rem);
}

.alert-heading {
    display: grid;
    grid-template-columns: auto 1fr;
    gap: 1.1rem;
    align-items: center;
    margin-bottom: 2rem;
}

.alert-icon {
    display: grid;
    width: 3.2rem;
    height: 3.2rem;
    place-items: center;
    border: 1px solid color-mix(in srgb,var(--danger) 48%,transparent);
    border-radius: 50%;
    background: var(--danger-bg);
    color: var(--danger);
    font: 700 1.35rem ui-monospace,SFMono-Regular,Consolas,monospace;
}

.eyebrow {
    margin: 0 0 .28rem;
    color: var(--danger);
    font: 600 .68rem ui-monospace,SFMono-Regular,Consolas,monospace;
    letter-spacing: .15em;
    text-transform: uppercase;
}

h2,h3,p {
    margin-top: 0;
}

h2 {
    margin: 0;
    color: var(--ink);
    font-size: clamp(1.55rem,5vw,2.35rem);
    line-height: 1.08;
    letter-spacing: -.045em;
}

h3 {
    margin: 0 0 .3rem;
    color: var(--muted);
    font: 600 .67rem ui-monospace,SFMono-Regular,Consolas,monospace;
    letter-spacing: .08em;
    text-transform: uppercase;
}

.target {
    margin: 0 0 1.75rem;
    padding: 1rem 1.1rem;
    border-left: 2px solid var(--target);
    background: color-mix(in srgb,var(--target) 6%,transparent);
}

.target p {
    margin: 0;
    overflow-wrap: anywhere;
    color: var(--ink);
    font: 500 .84rem ui-monospace,SFMono-Regular,Consolas,monospace;
}

.reasons {
    display: grid;
    gap: .65rem;
    margin: 0 0 1.75rem;
}

.reason {
    position: relative;
    padding: 1rem 1.1rem 1rem 3rem;
    border: 1px solid var(--line);
    background: color-mix(in srgb,var(--ink) 2%,transparent);
}

.reason:before {
    position: absolute;
    left: 1rem;
    top: 1.03rem;
    color: var(--danger);
    font: 700 .72rem ui-monospace,SFMono-Regular,Consolas,monospace;
    content: "×";
}

.reason h3 {
    color: var(--danger);
}

.reason p {
    margin: 0;
    color: var(--ink);
    font-size: .9rem;
}

.reason-critical {
    border-color: color-mix(in srgb,var(--danger) 36%,transparent);
    background: var(--danger-bg);
}

form {
    margin-top: 1.5rem;
    padding-top: 1.5rem;
    border-top: 1px solid var(--line);
}

input {
    font: inherit;
}

.btn,.btn-red {
    display: inline-flex;
    min-height: 2.85rem;
    align-items: center;
    justify-content: center;
    padding: .7rem 1.05rem;
    border: 1px solid var(--line);
    border-radius: 0;
    background: transparent;
    color: var(--ink);
    font-size: .8rem;
    font-weight: 750;
    cursor: pointer;
}

.btn:hover {
    border-color: var(--accent);
    color: var(--accent);
}

.btn-red {
    border-color: var(--danger);
    background: var(--danger);
    color: var(--danger-ink);
}

.btn-red:hover {
    filter: brightness(1.08);
}

.footnote {
    margin: 1.4rem 0 0;
    color: var(--muted);
    font: 400 .66rem ui-monospace,SFMono-Regular,Consolas,monospace;
}

@media(max-width:520px) {
    body {
        padding: 1rem;
    }
    .brand {
        margin-left: 0;
    }
    .message {
        padding: 1.35rem;
    }
    .alert-heading {
        grid-template-columns: 1fr;
    }
    .alert-icon {
        width: 2.7rem;
        height: 2.7rem;
    }
    .reason {
        padding-left: 2.7rem;
    }
}

@media(prefers-reduced-motion:reduce) {
    * {
        scroll-behavior: auto!important;
        transition: none!important;
    }
}

.tls-details {
    margin-top: 1.5rem;
    border-top: 1px solid var(--line);
    padding-top: 1rem;
}

.tls-details summary {
    cursor: pointer;
    color: var(--ink);
    font-weight: 650;
}

.tls-details[open] summary {
    margin-bottom: 1.25rem;
}

.tls-details dl {
    margin-bottom: 0;
}

.tls-details dt {
    color: var(--muted);
    font-size: .8rem;
    margin-top: .85rem;
}

.tls-details dd {
    margin: .2rem 0 0;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    font: .8rem ui-monospace,SFMono-Regular,Consolas,monospace;
}

.tls-details>p {
    color: var(--muted);
    font-size: .8rem;
}
</style>
</head>
<body>
    <main class="windowlet">
        <div class="brand">
            <img alt="" src="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA2NCA2NCIgcm9sZT0iaW1nIiBhcmlhLWxhYmVsbGVkYnk9InRpdGxlIGRlc2MiPgogIDx0aXRsZSBpZD0idGl0bGUiPlNtaXRocHJveHk8L3RpdGxlPgogIDxkZXNjIGlkPSJkZXNjIj5BIHRpbHRlZCBpbnNwZWN0aW9uIGF4aXMgcGFzc2luZyB0aHJvdWdoIGEgcm90YXRpbmcgc3BoZXJlPC9kZXNjPgogIDxwYXRoIGQ9Ik00MCA0IDI0IDYwIiBmaWxsPSJub25lIiBzdHJva2U9IiNlZWY3ZjIiIHN0cm9rZS13aWR0aD0iMyIvPgogIDxjaXJjbGUgY3g9IjMyIiBjeT0iMzIiIHI9IjEyIiBmaWxsPSIjMDcxMTBmIiBzdHJva2U9IiM4M2YyOGYiIHN0cm9rZS13aWR0aD0iMy40Ii8+CiAgPHBhdGggZD0ibTE1IDI3IDcgMm0yMCA2IDcgMiIgZmlsbD0ibm9uZSIgc3Ryb2tlPSIjODNmMjhmIiBzdHJva2Utd2lkdGg9IjIuNiIvPgo8L3N2Zz4K">
            <span>
                smithproxy
                <small>
                    traffic inspection proxy
                </small>
            </span>
        </div>
        <section class="windowlet-screen">
            <div class="message">
                <header class="alert-heading">
                    <div class="alert-icon" aria-hidden="true">
                        !
                    </div>
                    <div>
                        <p class="eyebrow">
                            Connection blocked
                        </p>
                        <h2>
                            TLS security warning
                        </h2>
                    </div>
                </header>
                <section class="target">
                    <h3>
                        Requested site
                    </h3>
                    <p>
                        {{ target }}
                    </p>
                </section>
                <div class="reasons">
                    {{ reasons }}
                </div>
                {{ action }}
                {{ details }}
                <p class="footnote">
                    Request blocked locally by Smithproxy TLS policy.
                </p>
            </div>
        </section>
    </main>
</body>
</html>
)sx_template"},
        {"templates/replacement/en/tls_replacement_dark.txt", R"sx_template(<!doctype html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width,initial-scale=1">
        <meta name="color-scheme" content="dark">
        <meta name="theme-color" content="#111417">
        <title>
            TLS security warning
        </title>
    <style>
:root {
    --bg: #111417;
    --bg2:#161b20;
    --panel: #1b2025;
    --ink: #f1f4f5;
    --muted: #9aa5ad;
    --line: rgba(210,220,225,.16);
    --accent: #a8b5bd;
    --target: #8ec5d8;
    --danger: #ff7b72;
    --danger-ink: #210604;
    --danger-bg: rgba(255,123,114,.09);
    --glow: rgba(77,105,120,.12);
    --card-shadow: rgba(0,0,0,.38);
}
{% include tls_replacement_common.txt %}
)sx_template"},
        {"templates/replacement/en/tls_replacement_error.txt", R"sx_template(<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>TLS replacement error</title></head>
<body>
    <p>Failed to override</p>
    <p>{{ message }}</p>
</body>
</html>
)sx_template"},
        {"templates/replacement/en/tls_replacement_light.txt", R"sx_template(<!doctype html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width,initial-scale=1">
        <meta name="color-scheme" content="light">
        <meta name="theme-color" content="#edf3ef">
        <title>
            TLS security warning
        </title>
    <style>
:root {
    --bg: #edf3ef;
    --bg2:#f7faf8;
    --panel: #ffffff;
    --ink: #132019;
    --muted: #66756d;
    --line: rgba(28,55,42,.18);
    --accent: #187a48;
    --target: #137b82;
    --danger: #bc3e37;
    --danger-ink: #ffffff;
    --danger-bg: rgba(188,62,55,.075);
    --glow: rgba(65,170,110,.12);
    --card-shadow: rgba(30,55,43,.14);
}
{% include tls_replacement_common.txt %}
)sx_template"},
    };
    return templates;
}

} // namespace sx::resources::default_templates
