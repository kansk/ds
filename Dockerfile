FROM baseimage
COPY . /opt/discovery
WORKDIR /opt/discovery
RUN chmod +x entrypoint.sh
ENTRYPOINT ["/opt/discovery/entrypoint.sh"]


