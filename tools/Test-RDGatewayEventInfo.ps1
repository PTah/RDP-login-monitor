# Проверка парсинга UserData/EventInfo для RD Gateway 303 (BytesReceived != ErrorCode).
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$sample303 = @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-TerminalServices-Gateway" />
    <EventID>303</EventID>
    <TimeCreated SystemTime="2026-06-02T23:51:21.033855700Z" />
  </System>
  <UserData>
    <EventInfo xmlns="aag">
      <Username>B26\TSA</Username>
      <IpAddress>95.154.72.73</IpAddress>
      <Resource>192.168.164.43</Resource>
      <BytesReceived>1991</BytesReceived>
      <BytesTransfered>2116</BytesTransfered>
      <SessionDuration>0</SessionDuration>
      <ConnectionProtocol>HTTP</ConnectionProtocol>
      <ErrorCode>1226</ErrorCode>
    </EventInfo>
  </UserData>
</Event>
'@

function Get-RDGatewayUserDataEventInfoMapFromXmlText {
    param([string]$XmlText)
    $map = @{}
    $xml = [xml]$XmlText
    $eventInfo = $xml.Event.UserData.EventInfo
    foreach ($node in @($eventInfo.ChildNodes)) {
        if ($null -eq $node -or $node.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
        $map[$node.LocalName] = [string]$node.InnerText
    }
    return $map
}

$map = Get-RDGatewayUserDataEventInfoMapFromXmlText -XmlText $sample303
if ($map['ErrorCode'] -ne '1226') {
    throw "Expected ErrorCode=1226, got $($map['ErrorCode'])"
}
if ($map['BytesReceived'] -ne '1991') {
    throw "Expected BytesReceived=1991, got $($map['BytesReceived'])"
}
if ($map['SessionDuration'] -ne '0') {
    throw "Expected SessionDuration=0, got $($map['SessionDuration'])"
}
Write-Host 'OK: RD Gateway EventInfo XML fields parsed correctly (ErrorCode != BytesReceived).'
