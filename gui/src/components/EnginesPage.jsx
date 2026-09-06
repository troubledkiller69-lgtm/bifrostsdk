import React from 'react';

const ENGINES = [
  {
    id: 'unreal',
    name: 'Unreal Engine',
    tag: 'UE4 / UE5',
    tagColor: '#3a8fb7',
    accent: '#3a8fb7',
    desc: 'GObjects, GNames, GWorld pointer chains. Supports UE4.25+ and UE5.',
  },
  {
    id: 'unity',
    name: 'Unity (Mono)',
    tag: 'IL2CPP / Mono',
    tagColor: '#43d9ad',
    accent: '#43d9ad',
    desc: 'Assembly-CSharp metadata, class hierarchy, field offsets via Il2Cpp reflection.',
  },
  {
    id: 'source',
    name: 'Source Engine',
    tag: 'CS2 / TF2',
    tagColor: '#d4a843',
    accent: '#d4a843',
    desc: 'Interface dumping, NetVar tables, ConVar scanning. Source 2 schema system.',
  },
  {
    id: 'blizzard',
    name: 'Blizzard ECS',
    tag: 'OW2',
    tagColor: '#e84057',
    accent: '#e84057',
    desc: 'Entity-Component-System with RTTI scanning. Hero archetypes and view matrix.',
  },
  {
    id: 'source_eac',
    name: 'Source (EAC)',
    tag: 'APEX',
    tagColor: '#ff6b35',
    accent: '#ff6b35',
    desc: 'Modified Source engine (r5 branch). Player, weapon, glow structs. EAC-aware.',
  },
  {
    id: 'custom',
    name: 'Custom / Generic',
    tag: 'AOB',
    tagColor: '#6b7d94',
    accent: '#6b7d94',
    desc: 'Pattern-based scanning for any game. Define custom signatures and struct layouts.',
  },
];

export default function EnginesPage({ selected, onSelect }) {
  return (
    <>
      <div className="page-header">
        <div className="page-title">Select Engine</div>
        <div className="page-subtitle">Choose the game engine to target for offset dumping</div>
      </div>

      <div className="engine-grid">
        {ENGINES.map((engine) => (
          <div
            key={engine.id}
            className={`engine-card ${selected === engine.id ? 'selected' : ''}`}
            style={{ '--card-accent': engine.accent }}
            onClick={() => onSelect(engine.id)}
          >
            <div className="engine-card-header">
              <span className="engine-card-name">{engine.name}</span>
              <span
                className="engine-card-tag"
                style={{ background: `${engine.tagColor}22`, color: engine.tagColor }}
              >
                {engine.tag}
              </span>
            </div>
            <div className="engine-card-desc">{engine.desc}</div>
          </div>
        ))}
      </div>
    </>
  );
}
