# Phishdet

Phishdet reads an email and estimates whether it is phishing. Paste a message, point it at an `.eml` file, or open the local page.

A logistic regression model scores the wording. Separate checks then look at the sender, the links, attachments, and a few high-signal phrases. The final verdict is those two pieces combined. The check does not open a link from the message.

## Run

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
phishdet --sample phishing
phishdet path/to/message.eml
phishdet --sample reset --json
phishdet serve
```

`phishdet serve` listens on `http://127.0.0.1:8000/`. Paste a message or choose a `.eml` file. The page scores the message locally, then looks up domain age, urlscan, and VirusTotal for the public domains in it. The built-in examples are a PayPal lookalike, a real-domain password reset, an ordinary work note, and a wire-transfer lure.

The hosted page is [GitHub Pages](https://ankitmallick800.github.io/PhisDet/). It sends the pasted message to the API at `https://phishingdetector-flax.vercel.app`. That API does not open links from the message. `VIRUSTOTAL_API_KEY` and `URLSCAN_API_KEY` are set on the Vercel project, not in the page.

```bash
phishdet --intel --sample reset
```

`--intel` runs the same lookups from the terminal. Without it, the terminal check stays on this computer and only reads headers that are already in the file.

From a pipe:

```bash
phishdet - < message.eml
```

Exit status is `0` when a verdict was produced, and `1` when the input could not be read. The verdict itself is in the output.

## How a message is scored

The text model is a TF-IDF vectorizer (word unigrams and bigrams, 20,000 features) followed by class-balanced logistic regression. It was trained on the public [Phishing Email Dataset](https://huggingface.co/datasets/zefang-liu/phishing-email-dataset) (a copy of the Kaggle set published by Subhajournal, LGPL-3.0). After dropping empty and duplicate rows, that is 17,121 emails: 6,188 phishing and 10,933 legitimate.

On a stratified 20% hold-out (3,425 emails):

| | |
| --- | --- |
| Precision | 0.968 |
| Recall | 0.986 |
| F1 | 0.976 |
| ROC-AUC | 0.997 |
| Accuracy | 0.983 |

The corpus labels scam and spam together with phishing, and it is mostly English. A message can be marked phishing because it reads like that mail even when no link looks wrong. The verdict says so when that happens.

The other checks are fixed, named signals. They cover lookalike and homoglyph domains, link text that disagrees with the destination, raw IP addresses, `@` tricks in URLs, password fields, risky attachments, reply-to mismatches, shorteners and odd TLDs paired with a credential ask, and payment requests from free webmail. A link that stays on a known organization's own domain pulls the score down, which is what keeps a normal GitHub or bank password reset from being flagged. A brand-new domain that is used consistently gets only a small benefit, because that pattern is easy for a phish to copy.

Signal weights are added to the text model's log-odds and squashed back into a probability. If a sender or link signal fired, 50% or more is phishing. If the wording is the only evidence, the bar is 70%, because short ordinary notes can sit near 50%.

## Headers, domain age, and reputation

The page reads `Authentication-Results`, `Received-SPF`, and `DKIM-Signature` from the paste. SPF, DKIM, or DMARC `fail` raises the score. A sender can forge those headers, so trust them when your mail server wrote them.

For each public domain in the From line, Reply-To, or a link, the page asks:

- RDAP (`https://rdap.org`) for the registration date. A domain under 14 days old adds a strong signal. Under 90 days adds a smaller one. No record is shown as "no record" and is not treated as new. Addresses on localhost, a private IP, or a reserved name such as `example.com` are skipped.
- [VirusTotal](https://www.virustotal.com/) API v3, if `VIRUSTOTAL_API_KEY` is set. The key is sent as a header. A missing report is left missing. The tool does not submit the URL for a new scan.
- [urlscan](https://urlscan.io/) search for an existing public scan. `URLSCAN_API_KEY` is optional and raises the rate limit. A scan counts only when urlscan marks that same domain malicious. The page does not ask urlscan to visit the URL.

Copy `.env.example` to `.env` to set the keys. Only the domain or URL from the message is sent. Old domains are shown and do not lower the score.

## Train again

The CSV is not part of the project. `scripts/train.py` reads `data/raw/Phishing_Email.csv` and writes `src/phishdet/artifacts/text_model.joblib`. If the CSV is missing, the script downloads the Hugging Face copy. The copy used for the checked-in model has SHA-256 `18ef4fff1acb8986f0ab01e83ede6025420c829656af5a377560fce17e153b97`.

```bash
python scripts/train.py
```

Held-out scores are also in `src/phishdet/artifacts/metrics.json`.

## Limits

- A legitimate result is not permission to click, reply, or pay.
- A forged `From` line on an otherwise clean message can look real. Pasted authentication headers can be forged too.
- The tool does not visit links, so it cannot see where a redirect ends. Reputation checks use existing RDAP, VirusTotal, and urlscan records.
- VirusTotal stays blank until `VIRUSTOTAL_API_KEY` is set. The free tier is only a few lookups a minute.
- Short messages and lure styles that are not in the training corpus are harder for the text model. The link and sender checks still apply.
- Outlook `.msg` files are not parsed. Save as `.eml`, or paste the text.

## Tests

```bash
pip install -e ".[dev]"
pytest
```
