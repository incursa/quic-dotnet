FROM mcr.microsoft.com/dotnet/sdk:10.0.201 AS build
WORKDIR /src

COPY . .
RUN dotnet restore samples/Incursa.Http3.Samples.TechEmpower/Incursa.Http3.Samples.TechEmpower.csproj
RUN dotnet publish samples/Incursa.Http3.Samples.TechEmpower/Incursa.Http3.Samples.TechEmpower.csproj --configuration Release --no-restore --output /app/publish

FROM mcr.microsoft.com/dotnet/runtime:10.0 AS runtime
WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates wget \
    && wget -O /tmp/packages-microsoft-prod.deb https://packages.microsoft.com/config/ubuntu/24.04/packages-microsoft-prod.deb \
    && dpkg -i /tmp/packages-microsoft-prod.deb \
    && apt-get update \
    && apt-get install -y --no-install-recommends libmsquic \
    && rm -rf /var/lib/apt/lists/* /tmp/packages-microsoft-prod.deb

COPY --from=build /app/publish .

ENV PROTOCOL_LAB_H3_PORT=5444
ENV PROTOCOL_LAB_IMPLEMENTATION=incursa-http3

EXPOSE 5444/udp

ENTRYPOINT ["dotnet", "Incursa.Http3.Samples.TechEmpower.dll"]
