FROM rishabhpoddar/supertokens_core_testing

RUN apt update && apt install software-properties-common -y

RUN curl -sL https://deb.nodesource.com/setup_10.x -o nodesource_setup.sh

RUN chmod +x nodesource_setup.sh

RUN ./nodesource_setup.sh

RUN apt-get install -y nodejs

RUN apt-get update

RUN apt-get install -y gconf-service libasound2 libatk1.0-0 libc6 libcairo2 libcups2 libdbus-1-3 libexpat1 libfontconfig1 libgcc1 libgconf-2-4 libgdk-pixbuf2.0-0 libglib2.0-0 libgtk-3-0 libnspr4 libpango-1.0-0 libpangocairo-1.0-0 libstdc++6 libx11-6 libx11-xcb1 libxcb1 libxcomposite1 libxcursor1 libxdamage1 libxext6 libxfixes3 libxi6 libxrandr2 libxrender1 libxss1 libxtst6 ca-certificates fonts-liberation libappindicator1 libnss3 lsb-release xdg-utils wget zlib1g-dev

RUN apt-get update

RUN wget https://www.python.org/ftp/python/3.7.12/Python-3.7.12.tgz

RUN tar -xvzf Python-3.7.12.tgz

RUN cd Python-3.7.12 && ./configure && make && make install && cd .. && rm -rf Python-3.7.12*

RUN update-alternatives --install /usr/bin/python3 python3 /usr/local/bin/python3.7 1

RUN echo 'alias pip=pip3\nalias python=python3.7' >> ~/.bashrc