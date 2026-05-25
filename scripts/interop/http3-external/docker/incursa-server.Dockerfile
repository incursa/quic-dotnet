FROM mcr.microsoft.com/dotnet/sdk:10.0.201 AS build
WORKDIR /src
COPY . .
RUN dotnet restore Incursa.Quic.slnx
RUN dotnet publish samples/Incursa.Quic.Http3.FileServer/Incursa.Quic.Http3.FileServer.csproj -c Release -o /app/publish --no-restore

FROM mcr.microsoft.com/dotnet/runtime:10.0
WORKDIR /app
COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "Incursa.Quic.Http3.FileServer.dll"]
