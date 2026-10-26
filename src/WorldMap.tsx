import { useMemo, useState } from "react";
import { geoNaturalEarth1, geoPath } from "d3-geo";
import { feature } from "topojson-client";
import world from "world-atlas/countries-110m.json";
import { Globe2, Minus, Plus, RotateCcw } from "lucide-react";
import { Empty, Panel } from "./components";
import type { Snapshot } from "./types";
const countries = (feature(world as any, world.objects.countries as any) as any)
  .features;
const projection = geoNaturalEarth1().fitExtent(
  [
    [15, 20],
    [945, 465],
  ],
  { type: "Sphere" },
);
const path = geoPath(projection);
const normalize = (name: string) =>
  name === "United States of America" ? "United States" : name;
export default function WorldMap({
  data,
  onSettings,
}: {
  data: Snapshot;
  onSettings: () => void;
}) {
  const [zoom, setZoom] = useState(1);
  const [selected, setSelected] = useState<string | null>(null);
  const located = data.connections.filter((c) => c.geo && c.remote_ip);
  const stats = useMemo(() => {
    const map = new Map<
      string,
      { count: number; endpoints: Set<string>; suspicious: number }
    >();
    for (const c of located) {
      const name = normalize(c.geo!.country);
      const row = map.get(name) || {
        count: 0,
        endpoints: new Set<string>(),
        suspicious: 0,
      };
      row.count++;
      row.endpoints.add(c.remote_ip!);
      if (c.threat) row.suspicious++;
      map.set(name, row);
    }
    return map;
  }, [data.connections]);
  const endpoints = [...new Map(located.map((c) => [c.remote_ip, c])).values()];
  const selectedRows = located.filter(
    (c) => normalize(c.geo!.country) === selected,
  );
  return (
    <>
      <div className="map-topline">
        <span>
          <Globe2 size={18} />
          {stats.size} located countries · {endpoints.length} remote endpoints
        </span>
        <span className="muted">
          {data.connections.filter((c) => c.remote_ip && !c.geo).length}{" "}
          connections have no location
        </span>
      </div>
      <Panel
        title="Your network, across borders"
        action={
          <div className="map-tools">
            <button
              className="icon-button"
              aria-label="Zoom in"
              disabled={zoom >= 3}
              onClick={() => setZoom((z) => Math.min(3, z + 0.5))}
            >
              <Plus size={17} />
            </button>
            <button
              className="icon-button"
              aria-label="Zoom out"
              disabled={zoom <= 1}
              onClick={() => setZoom((z) => Math.max(1, z - 0.5))}
            >
              <Minus size={17} />
            </button>
            <button
              className="icon-button"
              aria-label="Reset map"
              onClick={() => {
                setZoom(1);
                setSelected(null);
              }}
            >
              <RotateCcw size={16} />
            </button>
          </div>
        }
      >
        <div className="map-viewport">
          <svg
            viewBox="0 0 960 490"
            className="world-map"
            aria-label="Political world map with observed network endpoints"
          >
            <g
              transform={
                "translate(480 245) scale(" + zoom + ") translate(-480 -245)"
              }
            >
              {countries.map((country: any) => {
                const name = normalize(country.properties.name);
                const active = stats.has(name);
                return (
                  <path
                    key={country.id}
                    d={path(country) || ""}
                    className={
                      "country " +
                      (active ? "located " : "") +
                      (selected === name ? "selected" : "")
                    }
                    role="button"
                    tabIndex={0}
                    aria-label={
                      name +
                      ": " +
                      (stats.get(name)?.count || 0) +
                      " located connections"
                    }
                    onClick={() => setSelected(name)}
                    onKeyDown={(event) => {
                      if (event.key === "Enter" || event.key === " ") {
                        event.preventDefault();
                        setSelected(name);
                      }
                    }}
                  >
                    <title>{name}</title>
                  </path>
                );
              })}
              {endpoints.map((c) => {
                const point = projection([c.geo!.lon, c.geo!.lat]);
                return point ? (
                  <circle
                    key={c.remote_ip}
                    cx={point[0]}
                    cy={point[1]}
                    r={c.threat ? 5 : 3.5}
                    className={"endpoint " + (c.threat ? "suspicious" : "")}
                  >
                    <title>
                      {c.remote_ip} · {c.geo!.country}
                      {c.threat ? " · Threat feed match" : ""}
                    </title>
                  </circle>
                ) : null;
              })}
            </g>
          </svg>
          {!data.coverage.geo.available && (
            <div className="map-empty">
              <Globe2 size={30} />
              <h3>Add a local GeoIP database</h3>
              <p>
                Locate real connections without sending your IP history to a
                geolocation service.
              </p>
              <button className="primary" onClick={onSettings}>
                Set up geolocation
              </button>
            </div>
          )}
        </div>
        <div className="map-caption">
          <span>
            <i className="download-dot" />
            Observed endpoint
          </span>
          <span>
            <i className="danger-dot" />
            Threat feed match
          </span>
          <small>
            Approximate locations, not device positions. Borders: Natural Earth. {data.coverage.geo.provider?.toLowerCase().includes("dbip") && <a href="https://db-ip.com/" target="_blank" rel="noreferrer">IP Geolocation by DB-IP</a>}
          </small>
        </div>
      </Panel>
      <div className="two-columns">
        <Panel title="Country statistics">
          {stats.size ? (
            <div className="country-list">
              {[...stats.entries()]
                .sort((a, b) => b[1].count - a[1].count)
                .map(([name, row]) => (
                  <button
                    key={name}
                    className={
                      "country-row " + (selected === name ? "selected" : "")
                    }
                    onClick={() => setSelected(name)}
                  >
                    <span>
                      {name}
                      <small>
                        {row.endpoints.size} endpoints · {row.suspicious} threat
                        matches
                      </small>
                    </span>
                    <strong>
                      {row.count}
                      <small>connections</small>
                    </strong>
                  </button>
                ))}
            </div>
          ) : (
            <Empty title="No located connections">
              Private addresses and addresses missing from your database remain
              unlocated.
            </Empty>
          )}
        </Panel>
        <Panel title={selected || "Explore a country"}>
          {selectedRows.length ? (
            <div className="country-list">
              {selectedRows.slice(0, 30).map((c) => (
                <div key={c.id} className="evidence">
                  <strong className="mono">
                    {c.remote_ip}:{c.remote_port}
                  </strong>
                  <p>
                    {c.domain || "Domain not observed"} · {c.protocol} ·{" "}
                    {c.geo?.city || "City unavailable"}
                  </p>
                </div>
              ))}
              {selectedRows.length > 30 && (
                <p>
                  Showing the first 30 of {selectedRows.length} connections.
                </p>
              )}
            </div>
          ) : (
            <Empty
              title={
                selected ? "No observed endpoints here" : "Select a country"
              }
            >
              Click a country on the map or in the statistics to inspect its
              connections. Geography does not affect risk scores.
            </Empty>
          )}
        </Panel>
      </div>
    </>
  );
}
