/**
 * @file GeneratorView.jsx
 *
 * The password generator. Strength is explained in words (why it is weak or
 * strong, in bits of entropy), not just shown as a coloured bar.
 *
 * The settings chosen here are remembered on this device and also used by
 * the "Generate" button in the item form.
 */

import { RefreshCw } from "lucide-react";
import { useEffect, useState } from "react";

import {
  MAX_GENERATED_LENGTH,
  MIN_GENERATED_LENGTH,
  describeStrength,
  estimateEntropyBits,
  generatePassword,
} from "@tessera/crypto";

import { usePreference } from "../hooks/usePreference.js";
import { CopyButton } from "./common.jsx";

export const DEFAULT_GENERATOR_OPTIONS = Object.freeze({
  length: 20,
  lowercase: true,
  uppercase: true,
  digits: true,
  symbols: true,
  excludeAmbiguous: false,
});

const characterTypeOptions = [
  { name: "lowercase", label: "Lowercase (a–z)" },
  { name: "uppercase", label: "Uppercase (A–Z)" },
  { name: "digits", label: "Digits (0–9)" },
  { name: "symbols", label: "Symbols (!@#…)" },
];

const strengthClasses = {
  weak: "strengthWeak",
  fair: "strengthFair",
  strong: "strengthStrong",
  excellent: "strengthExcellent",
};
const strengthSegments = { weak: 1, fair: 2, strong: 3, excellent: 4 };

export function GeneratorView() {
  const [options, setOptions] = usePreference("generatorOptions", DEFAULT_GENERATOR_OPTIONS);
  const [password, setPassword] = useState("");

  const enabledTypeCount = characterTypeOptions.filter((option) => options[option.name]).length;

  // Generate a new password whenever the options change.
  useEffect(() => {
    if (enabledTypeCount > 0) {
      setPassword(generatePassword(options));
    }
  }, [options, enabledTypeCount]);

  const updateOption = (name, value) => {
    const next = { ...options, [name]: value };
    // Keep at least one character type selected.
    if (characterTypeOptions.every((option) => !next[option.name])) {
      return;
    }
    setOptions(next);
  };

  const setLength = (rawValue) => {
    const length = Math.min(MAX_GENERATED_LENGTH, Math.max(MIN_GENERATED_LENGTH, Number(rawValue) || MIN_GENERATED_LENGTH));
    updateOption("length", length);
  };

  const entropyBits = estimateEntropyBits(options);
  const strength = describeStrength(entropyBits);

  return (
    <div className="pageView">
      <header className="pageHeader">
        <h1 className="pageTitle">Password generator</h1>
        <p className="pageLead">
          Random passwords from your browser’s cryptographic random number generator, with no bias toward any
          character.
        </p>
      </header>

      <div className="pageBody">
        <section className="section">
          <div>
            <h2 className="sectionTitle">Generated password</h2>
            <p className="sectionDescription">Copied passwords are cleared from the clipboard after 30 seconds.</p>
          </div>
          <div className="sectionContent">
            <div className="generatedOutput">
              <span className="generatedValue" aria-live="polite">
                {password}
              </span>
              <button
                type="button"
                className="iconButton"
                onClick={() => setPassword(generatePassword(options))}
                aria-label="Generate another"
                title="Generate another"
              >
                <RefreshCw aria-hidden="true" />
              </button>
              <CopyButton value={password} label="Copy password" isSecret />
            </div>

            <div className={`strength ${strengthClasses[strength.level]}`}>
              <div className="strengthMeter" aria-hidden="true">
                {[1, 2, 3, 4].map((segment) => (
                  <span
                    key={segment}
                    className={`strengthSegment ${segment <= strengthSegments[strength.level] ? "strengthSegmentOn" : ""}`}
                  />
                ))}
              </div>
              <p className="strengthSummary">
                <span className="strengthLabel">{strength.label}</span>{" "}
                <span className="strengthBits">≈ {Math.floor(entropyBits)} bits</span>{" "}
                <span className="strengthExplanation">{strength.explanation}</span>
              </p>
            </div>
          </div>
        </section>

        <section className="section">
          <div>
            <h2 className="sectionTitle">Length</h2>
            <p className="sectionDescription">Each extra character multiplies the number of possible passwords.</p>
          </div>
          <div className="sectionContent">
            <div className="lengthControl">
              <input
                className="range"
                type="range"
                min={MIN_GENERATED_LENGTH}
                max={64}
                value={Math.min(options.length, 64)}
                onChange={(event) => setLength(event.target.value)}
                aria-label="Password length"
              />
              <input
                className="input"
                type="number"
                min={MIN_GENERATED_LENGTH}
                max={MAX_GENERATED_LENGTH}
                value={options.length}
                onChange={(event) => setLength(event.target.value)}
                aria-label="Password length (number)"
              />
            </div>
          </div>
        </section>

        <section className="section">
          <div>
            <h2 className="sectionTitle">Characters</h2>
            <p className="sectionDescription">Every selected type is guaranteed to appear at least once.</p>
          </div>
          <div className="sectionContent">
            <div className="generatorOptions">
              {characterTypeOptions.map((option) => (
                <label key={option.name} className="checkboxRow">
                  <input
                    type="checkbox"
                    checked={options[option.name]}
                    onChange={(event) => updateOption(option.name, event.target.checked)}
                    disabled={options[option.name] && enabledTypeCount === 1}
                  />
                  {option.label}
                </label>
              ))}
            </div>
            <label className="checkboxRow">
              <input
                type="checkbox"
                checked={options.excludeAmbiguous}
                onChange={(event) => updateOption("excludeAmbiguous", event.target.checked)}
              />
              Avoid look-alike characters (I, l, 1, O, 0, o)
            </label>
          </div>
        </section>
      </div>
    </div>
  );
}
