# INF2005 ACW3 - untrusted backend for the mod_xml2enc proxy scenario.
# Standard library only, so no build step and no external packages.
FROM python:3.12-slim
WORKDIR /app
COPY app.py /app/app.py
EXPOSE 8000
USER nobody
CMD ["python3", "app.py"]
