# Plan integracji proxy z API dashboardu

Stan rozpoznania: 2026-10-04. Dokument opisuje plan prac, a nie stan wdrożenia.

## Cel i przyjęte decyzje

Dashboard jest źródłem prawdy dla tenantów, konfiguracji runtime, polityk i
poświadczenia JEV. Proxy pobiera dane przez wersjonowane API dashboardu i
egzekwuje zweryfikowany, podpisany bundle. MongoDB zostaje całkowicie usunięte
z proxy. Wartości sterujące zachowaniem narzędzi i decyzji pochodzą z dashboardu;
obecne stałe w `source/bootstrap.ts` są tylko mockami i zostają usunięte.

Proxy zachowuje na lokalnym dysku atomowo zapisaną kopię ostatniego poprawnego
bundle. Jest to kopia danych z API, nie osobne źródło konfiguracji ani MongoDB.
Pozwala obsługiwać żądania, gdy dashboard jest niedostępny. Żadne żądanie
chronionej aplikacji nie czeka na odpowiedź dashboardu. Redis może nadal
służyć do nietrwałego cache i kontekstu runtime.

## Stan wyjściowy

- Proxy nie pobiera bundle, poświadczenia JEV ani nie wysyła heartbeatów lub
  telemetrii. Plan narzędzi, konfiguracja runtime, zachowania przy awarii,
  `UPSTREAM_URL` i klucz JEV są obecnie ustawiane lokalnie.
- Dashboard udostępnia `GET /api/v1/tenants/:tenantId/active-bundle`,
  `GET /api/v1/proxy/jev-credential`, `POST /api/v1/proxy/heartbeats` i
  `POST /api/v1/proxy/telemetry`. Uwierzytelnia je kluczem wdrożeniowym z
  odpowiednimi zakresami uprawnień.
- Bundle `tessera.bundle/v1` zawiera konfigurację runtime i politykę. Obecny
  rejestr narzędzi dashboardu `tessera.tools/v1` kompiluje tylko
  `string_length` z `minLength` i `maxLength`.
- Dashboard wydaje identyfikatory tenantów w formacie MongoDB `ObjectId`,
  natomiast proxy wymaga UUID v4 przy tworzeniu przestrzeni kluczy Redis.
- Normalizator proxy tworzy osobno nazwę pola i jego lokalizację, a kontrakt
  dashboardu używa celów takich jak `body.username`. Proxy używa ścieżki
  żądania, podczas gdy polityka może zawierać wzorzec `/users/:id`.

## Etap 1: wspólny kontrakt sieciowy

**Dashboard i proxy**

1. Utrzymywać wersjonowane kontrakty w `source/shared/contracts` proxy;
   dashboard zachowuje zgodne definicje transportowe. Proxy nie importuje kodu
   aplikacyjnego backendu dashboardu.
   Uwzględnić schematy bundle, narzędzi, heartbeatów, telemetrii i odpowiedzi
   z poświadczeniem JEV.
2. Przyjąć identyfikator tenanta wydawany przez dashboard. Zmienić walidację
   identyfikatora w proxy i zachować izolację przestrzeni kluczy Redis.
3. Określić jedną reprezentację klucza endpointu `METHOD /policy/path` oraz
   dopasowanie wzorców ścieżek do konkretnych żądań. Ustalić semantykę celów
   pól `body.*`, `query.*` i ewentualnych dalszych lokalizacji.
4. Rozszerzyć kontrakt dashboardu o wartości potrzebne obecnemu mechanizmowi
   decyzji proxy, których `tessera.bundle/v1` jeszcze nie przenosi: progi JEV,
   granice adaptacyjnego próbkowania i zachowania dla konkretnych awarii.
   Nie utożsamiać ogólnego `failureBehavior` z każdą z tych decyzji. Zmiany
   formatu publikować pod nową wersją schematu i negocjować jej obsługę.
5. Przyjąć `bundle.version` jako identyfikator konfiguracji użytej do decyzji;
   `policyVersion` może być inny, gdy zmieni się konfiguracja runtime.

**Warunek zakończenia:** oba repozytoria walidują te same przykładowe payloady i
jednakowo interpretują tenant, endpoint, cel pola oraz konfigurację decyzji.

## Etap 2: usunięcie MongoDB i dystrybucja bundle

**Proxy**

1. Usunąć inicjalizację i zamykanie MongoDB, moduły magazynu i repozytoriów,
   zależność `mongodb` oraz zmienne `MONGO_URL`, `MONGO_DB_NAME` i
   `TENANT_DB_NAME`.
2. Dodać klienta `GET /api/v1/tenants/:tenantId/active-bundle` z kluczem
   wdrożeniowym, nagłówkami `Tessera-Bundle-Schemas` i
   `Tessera-Tool-Registries` oraz obsługą `ETag` / `If-None-Match`.
3. Przed użyciem bundle sprawdzać podpis Ed25519 nad kanonicznym JSON,
   zaufany klucz publiczny, `tenantId`, wersję schematu, hash `version`,
   wersję rejestru oraz identyfikator i konfigurację każdego narzędzia.
   Odrzucenie jednego elementu odrzuca cały bundle.
4. Po pełnej weryfikacji zapisywać bundle atomowo do lokalnego pliku. Przy
   błędzie pobrania lub weryfikacji ładować ostatnią poprawną kopię. Nie
   zastępować nią działającego snapshotu podczas obsługi żądań.
5. Pobierać aktywny bundle na starcie. Późniejsze sprawdzenie `ETag` może
   zgłosić, że potrzebny jest restart, ale nie przełącza aktywnej polityki
   w działającym procesie.

**Warunek zakończenia:** proxy działa bez MongoDB; awaria API, uszkodzony
podpis, obce `tenantId` lub nieznane narzędzie nie zastępują poprawnej polityki.

## Etap 3: egzekwowanie konfiguracji dashboardu

**Proxy**

1. Zastąpić `PLACEHOLDER_PLAN`, `PLACEHOLDER_RUNTIME_CONFIG`,
   `FAILURE_POLICY` i lokalny `UPSTREAM_URL` wartościami ze zweryfikowanego
   snapshotu. W środowisku pozostają tylko ustawienia potrzebne do połączenia
   z dashboardem, identyfikacji wdrożenia i weryfikacji podpisu oraz ustawienia
   samego procesu, takie jak port nasłuchu.
2. Dopasować żądanie do endpointu z polityki, wybrać jego plan narzędzi i
   poprawnie rozwiązać cel pola. Dla braku dopasowania stosować
   `unknownEndpointBehavior` z bundle.
3. Stosować `upstreamUrl`, `routing.pathPrefix`, `requestTimeoutMs`,
   `maxRequestBodyBytes`, próbkowanie i jawnie skonfigurowane zachowania przy
   awarii zgodnie z kontraktem. Nie dopowiadać brakujących ustawień stałymi
   z obecnego bootstrapu.
4. Wiązać decyzje, cache i raportowanie z wersją załadowanego bundle, aby
   nie używać wyników dla niezgodnej polityki.

**Warunek zakończenia:** zmiana konfiguracji w dashboardzie, jej aktywacja i
restart proxy zmieniają zachowanie bez edycji konfiguracji proxy.

## Etap 4: konfiguracja narzędzi

**Dashboard i proxy**

1. W pierwszej kolejności dostosować `string_length` do `minLength` i
   `maxLength` przekazywanych w bundle. Usunąć stały próg `10`.
2. Zinwentaryzować pozostałe narzędzia ze stałymi wartościami wpływającymi
   na politykę: limity rozmiaru i liczby żądań, zakresy, okna czasowe, listy
   dozwolonych wartości oraz podobne parametry.
3. Dla każdego narzędzia, które ma być aktywowane, dodać schemat konfiguracji
   i kompilację po stronie dashboardu oraz walidację i wykonanie po stronie
   proxy. Konfiguracja trafia w podpisanym bundle. Narzędzie bez kompletnego
   kontraktu nie może znaleźć się w wykonywalnym rejestrze.
4. Zachować zgodność wersji rejestru narzędzi. Nowe możliwości wymagają
   jawnego ogłoszenia przez proxy i sprawdzenia zgodności przez dashboard.

**Warunek zakończenia:** zmiana parametru w dashboardzie daje przewidywalnie
inny wynik dla tego samego żądania; błędna konfiguracja jest odrzucana przed
aktywowaniem bundle.

## Etap 5: JEV i obserwowalność

**Proxy**

1. Pobierać klucz JEV z `GET /api/v1/proxy/jev-credential` przy użyciu
   uprawnienia `jev-credentials:read`; usunąć wymóg `TYPESAFE_API_KEY`.
   Przechowywać klucz wyłącznie w pamięci i nigdy go nie logować. Błąd
   pobrania zachowuje dotychczasowy klucz; `404` usuwa go zgodnie z ADR-0009.
2. Wysyłać heartbeat z identyfikatorem procesu, obsługiwanymi wersjami,
   źródłem bundle i faktycznie załadowaną wersją. Dashboard może wtedy
   pokazać stan `restart_required` lub niezgodność.
3. Agregować i wysyłać asynchronicznie minutową telemetrię liczników.
   Używać kluczy endpointów z załadowanej polityki, a nie surowych URL-i.
   Nie wysyłać treści żądań, nagłówków autoryzacji ani wartości pól.
   Awaria telemetrii nie wpływa na decyzję o żądaniu.

**Warunek zakończenia:** dashboard pokazuje stan proxy i liczniki po
rzeczywistym ruchu; rotacja lub odłączenie klucza JEV zachowuje się zgodnie
z kontraktem.

## Weryfikacja końcowa

Przejść pełną ścieżkę: utworzenie tenanta i klucza wdrożeniowego w dashboardzie,
aktywacja polityki, pobranie i weryfikacja bundle, restart proxy, żądania
`ALLOW`/`BLOCK`, heartbeat oraz telemetria widoczna w dashboardzie. Sprawdzić
osobno: obcy tenant, zmieniony podpis, nieobsługiwany schemat lub narzędzie,
awarię API po wcześniejszym poprawnym starcie i restart podczas tej awarii.

## Decyzja wymagana przed pierwszym uruchomieniem

Gdy proxy nigdy nie pobrało poprawnego bundle i nie ma lokalnej kopii, nie zna
`failureBehavior` danego tenanta. ADR-0005 pozostawia zachowanie w tej sytuacji
decyzji wdrożeniowej po stronie proxy. Trzeba wybrać i udokumentować jawne
zachowanie pierwszego startu bez bundle przed usunięciem mocków; plan nie
przyjmuje tu domyślnego `ALLOW` ani `BLOCK`.
