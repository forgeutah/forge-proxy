/* global React, ReactDOM, useAuthFlow, VariantCard, VariantTerminal, VariantSplit,
          TweaksPanel, useTweaks, TweakSection, TweakRadio, TweakSelect, TweakToggle, TweakButton */
/* eslint-disable no-unused-vars */

// =====================================================================
// Forge Auth Proxy — root app
// =====================================================================

const TWEAK_DEFAULTS = /*EDITMODE-BEGIN*/{
  "variant": "card",
  "state": "logged-out",
  "host": "deuce.forgeutah.tech",
  "ascii": true
}/*EDITMODE-END*/;

function AuthApp() {
  const [tweaks, setTweak] = useTweaks(TWEAK_DEFAULTS);

  // The flow is driven by the tweak-selected state. When the tweak changes,
  // the hook re-syncs internally.
  const flow = useAuthFlow(tweaks.state, tweaks.host);

  // When the user clicks the Slack button inside a variant, the flow goes
  // through connecting → success and we surface those state changes back
  // into the tweak so the Tweaks panel reflects reality.
  const wrappedFlow = React.useMemo(() => ({
    ...flow,
    startConnecting: () => {
      setTweak('state', 'connecting');
      // useAuthFlow's effect will re-kick the steps when initialState becomes 'connecting'
    },
  }), [flow.state, flow.stepIdx, flow.countdown]);

  // Mirror flow.state into the tweak when it advances to 'success' on its own.
  React.useEffect(() => {
    if (flow.state !== tweaks.state) {
      setTweak('state', flow.state);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [flow.state]);

  const Variant = tweaks.variant === 'terminal' ? VariantTerminal
                : tweaks.variant === 'split'    ? VariantSplit
                : VariantCard;

  return (
    <>
      <Variant
        flow={wrappedFlow}
        host={tweaks.host}
        withAscii={tweaks.ascii}
      />

      <TweaksPanel title="Tweaks">
        <TweakSection label="Layout">
          <TweakRadio
            label="Variant"
            value={tweaks.variant}
            options={[
              { value: 'card',     label: 'Card' },
              { value: 'terminal', label: 'Terminal' },
              { value: 'split',    label: 'Split' },
            ]}
            onChange={(v) => setTweak('variant', v)}
          />
          <TweakToggle
            label="ASCII flourishes"
            value={tweaks.ascii}
            onChange={(v) => setTweak('ascii', v)}
          />
        </TweakSection>

        <TweakSection label="State">
          <TweakSelect
            label="Auth state"
            value={tweaks.state}
            options={[
              { value: 'logged-out',   label: 'Logged out · sign in' },
              { value: 'connecting',   label: 'Connecting · OAuth round-trip' },
              { value: 'success',      label: 'Success · redirecting' },
              { value: 'error',        label: 'Error · auth failed' },
              { value: 'unauthorized', label: 'Unauthorized · not in workspace' },
              { value: 'logged-in',    label: 'Already signed in' },
            ]}
            onChange={(v) => setTweak('state', v)}
          />
          <TweakButton
            label="↻ Replay flow"
            onClick={() => setTweak('state', 'connecting')}
          />
        </TweakSection>

        <TweakSection label="Requested app">
          <TweakRadio
            label="Upstream"
            value={tweaks.host}
            options={[
              { value: 'deuce.forgeutah.tech',    label: 'Deuce' },
              { value: 'platform.forgeutah.tech', label: 'Platform' },
            ]}
            onChange={(v) => setTweak('host', v)}
          />
        </TweakSection>
      </TweaksPanel>
    </>
  );
}

ReactDOM.createRoot(document.getElementById('root')).render(<AuthApp />);
