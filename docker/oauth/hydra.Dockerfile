FROM oryd/hydra:v2.2.0
ENV DSN=sqlite:///var/lib/sqlite/db.sqlite?_fk=true
COPY hydra.yml /hydra.yml

RUN hydra migrate -c /hydra.yml sql -e --yes

EXPOSE 4444
EXPOSE 4445

CMD ["serve", "-c", "/hydra.yml", "all", "--dev"]
