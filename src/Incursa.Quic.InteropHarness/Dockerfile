FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY quic-dotnet/ /src/
RUN dotnet restore Incursa.Quic.slnx
RUN dotnet publish src/Incursa.Quic.InteropHarness/Incursa.Quic.InteropHarness.csproj -c Release -o /app/publish --no-restore

FROM mcr.microsoft.com/dotnet/runtime:10.0
WORKDIR /app
COPY --from=build /app/publish .
COPY quic-dotnet/src/Incursa.Quic.InteropHarness/run_endpoint.sh /app/run_endpoint.sh
RUN chmod +x /app/run_endpoint.sh
ENTRYPOINT ["/app/run_endpoint.sh"]
