import { useEffect, useRef, useState } from "react";
import { Bell, Check, ExternalLink, Radio, Rocket, ShieldCheck } from "lucide-react";
import { request } from "./api";
import { Toggle } from "./components";
import type { Snapshot } from "./types";

// First-run setup: the three choices that decide whether Beaver protects the user all day.
export default function Onboarding({
  data,
  update,
  busy,
}: {
  data: Snapshot;
  update: (patch: object) => Promise<void>;
  busy: boolean;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const [step, setStep] = useState(0);
  const [tested, setTested] = useState("");
  const capture = data.coverage.capture;
  const windows = data.coverage.platform === "Windows";
  useEffect(() => {
    if (!ref.current?.open) ref.current?.showModal();
  }, []);
  const finish = () => update({ onboarded: true });
  const steps = [
    {
      icon: Rocket,
      title: "Welcome to Beaver",
      body: (
        <>
          <p>
            Beaver watches every network connection on this computer, checks it against{" "}
            {data.coverage.intel.entries ? data.coverage.intel.entries.toLocaleString() : "225,000+"} threat indicators, and warns you when
            someone may be controlling your PC or taking your data. Everything stays on this device.
          </p>
          <Toggle
            label="Start Beaver when I sign in"
            description="Protection starts quietly in the tray at every sign-in. Recommended."
            checked={data.settings.start_at_login}
            disabled={busy}
            onChange={() => update({ start_at_login: !data.settings.start_at_login })}
          />
          <Toggle
            label="Keep running when I close the window"
            description="The window unloads to save memory; monitoring continues in the tray."
            checked={data.settings.close_to_tray}
            disabled={busy}
            onChange={() => update({ close_to_tray: !data.settings.close_to_tray })}
          />
        </>
      ),
    },
    {
      icon: Radio,
      title: "See which website every app talks to",
      body: (
        <>
          <p>
            Packet capture adds per-app upload/download speeds and website names (from DNS and the TLS handshake), which powers data-theft
            detection. Beaver reads packet headers only, never contents.
          </p>
          {capture.available ? (
            <Toggle
              label="Enable packet capture"
              description={
                capture.active
                  ? `Active on ${capture.interfaces ?? 0} interfaces.`
                  : capture.error || "Capture library found on this computer."
              }
              checked={data.settings.capture}
              disabled={busy}
              onChange={() => update({ capture: !data.settings.capture })}
            />
          ) : windows ? (
            <div className="inline-note">
              Install the free Npcap driver to enable this, then restart Beaver.{" "}
              <a href="https://npcap.com/#download" target="_blank" rel="noreferrer">
                Get Npcap <ExternalLink size={12} />
              </a>
            </div>
          ) : (
            <div className="inline-note">
              Install libpcap (<span className="mono">sudo apt install libpcap0.8</span>) to enable this. See docs/PLATFORMS.md for capture
              without root.
            </div>
          )}
          <p className="small muted">You can skip this. Connection monitoring, threat intelligence and remote-access detection work without it.</p>
        </>
      ),
    },
    {
      icon: Bell,
      title: "Get warned instantly",
      body: (
        <>
          <p>Beaver notifies you about high-risk activity and remote access, even when the window is closed. Notifications include buttons to end a session or block an app.</p>
          <Toggle
            label="Tell me when a new app goes online"
            description="One notification the first time a program connects to the internet. Existing apps are learned silently during the first 10 minutes."
            checked={data.settings.notify_new_apps}
            disabled={busy}
            onChange={() => update({ notify_new_apps: !data.settings.notify_new_apps })}
          />
          <button
            disabled={busy}
            onClick={() =>
              request("test_notification")
                .then(() => setTested("Sent. If nothing appeared, check Do Not Disturb / Focus Assist."))
                .catch((e) => setTested(e.message))
            }
          >
            <Bell size={15} />
            Send a test notification
          </button>
          {tested && <p className="small muted">{tested}</p>}
        </>
      ),
    },
  ];
  const current = steps[step];
  return (
    <dialog ref={ref} className="onboarding" aria-labelledby="onboarding-title" onCancel={(e) => e.preventDefault()}>
      <div className="dialog-content">
        <div className="onboarding-progress">
          {steps.map((_, i) => (
            <i key={i} aria-hidden="true" className={i <= step ? "done" : ""} />
          ))}
          <span className="sr-only">
            Step {step + 1} of {steps.length}
          </span>
        </div>
        <current.icon size={30} />
        <h2 id="onboarding-title">{current.title}</h2>
        <div className="onboarding-body">{current.body}</div>
        <div className="dialog-actions">
          {step ? (
            <button disabled={busy} onClick={() => setStep(step - 1)}>
              Back
            </button>
          ) : (
            <button disabled={busy} onClick={finish}>
              Skip setup
            </button>
          )}
          {step < steps.length - 1 ? (
            <button className="primary" disabled={busy} onClick={() => setStep(step + 1)}>
              Continue
            </button>
          ) : (
            <button className="primary" disabled={busy} onClick={finish}>
              <ShieldCheck size={15} />
              Start protecting
            </button>
          )}
        </div>
        {step === steps.length - 1 && (
          <p className="small muted onboarding-foot">
            <Check size={13} /> Change any of this later in Settings.
          </p>
        )}
      </div>
    </dialog>
  );
}
