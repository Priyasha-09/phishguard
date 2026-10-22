# PhishGuard

**AI-Powered Phishing URL and Scam Message Detector**

PhishGuard is a defensive cybersecurity project designed to help users assess suspicious URLs and messages using explainable security rules and, where appropriate, machine learning.

## Planned Features

* URL structure and suspicious-pattern analysis.
* Scam and phishing message analysis.
* Explainable risk scores and risk levels.
* Analysis history with privacy-conscious storage.
* Dashboard statistics and visualizations.
* CSV report export.
* Automated backend and frontend tests.
* Publicly deployed web application.

Features will be marked as implemented only after they have been developed and tested.

## Technology Stack

* **Frontend:** React, Vite, JavaScript, CSS.
* **Backend:** Python, FastAPI, Pydantic.
* **Database:** SQLite for local development.
* **Machine Learning:** Pandas and scikit-learn, subject to dataset suitability.
* **Testing:** Pytest and HTTPX.

## Security and Privacy

PhishGuard is intended for defensive analysis.

The application will analyze submitted URLs as strings without automatically visiting their destinations.

Submitted message contents will not be stored by default. Risk scores will be presented as estimates, not guarantees that content is safe or fraudulent.

## Project Status

Initial repository setup.

Implementation, testing, documentation, and deployment are pending.

## License

A project licence has not yet been selected. Reuse and redistribution permissions should not be assumed until a licence is added.
