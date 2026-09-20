# BIFROST — Design Direction (locked) — OG Fast & Furious / FM Green

> Toretto's garage at 1am. Not a showroom — a shop. Supra on jack stands, NOS bottle sweating lime, FM deck glowing `#7EFF3F` on black plastic, parking-garage sodium spilling orange across smoked gauge faces.

## Subject

We built the UI like you'd build a street car in 2001. Black dash plastic you can thumbprint, brushed aluminum with hairline scratches, analog boost needle at 14psi, green underglow humming under the chassis. High-tech would be an OLED showroom. This is analog + lime. The operator tunes the radio deck, not a lab bench. Job: pick engine → lock target → purge dump → read dents. The FM green and coolant green from your refs are the hero — NOS lime on void black, with garage warmth underneath.

## Palette — lime is the only pop (locked)

- Void shop — `#030303` deep dash plastic, surface `#0a0a0c` sheetmetal, panel `#121218` dim bay. Crushed, not clean.
- FM / NOS Green — `#7EFF3F` frequency lime (primary). Hi `#B8FF9A`, dim `rgba(126,255,63,0.16)`, active `rgba(126,255,63,0.42)`. Gradient `linear-gradient(180deg, #9EFF6B 0%, #7EFF3F 55%, #5ACC2A 100%)` with `inset 0 1px 0 rgba(255,255,255,0.22)` gel only on primary CTA. Used on: selected tick, focus ring, live readout, coolant tube fill. Nowhere else full-bleed.
- Sodium warm — `rgba(245,158,11,0.10)` + `#d97706` needle/amber filament. Not a second accent — only for analog gauges, warning glow, NOS pressure ticks. Keeps it 2001 parking garage, not RGB.
- Garage metal — brushed `#C8CDD0` at 0.10 opacity brushed hairlines, not chrome gloss. Titlebar is still black plastic with silver edge `1px rgba(200,205,208,0.14)`, not a silver face. No mirror chrome.
- Street black — buttons `#121218` `1px rgba(255,255,255,0.08)` border + top `rgba(255,255,255,0.10)` highlight, inset bevel. Legend `#f8fafc` silkscreen `10px 1.5px`, secondary `#94a3b8`, muted `#64748b`, live data `#7EFF3F` on `#030303` with `0 0 6px rgba(126,255,63,0.38)` phosphor glow.
- Borders: hairline `rgba(255,255,255,0.08)` plate, well `rgba(0,0,0,0.6)` inset, active `rgba(126,255,63,0.42)`. Radius `5/3/8` but panels keep soft `4-5px` — not laser cut. Analog corners slightly smoked.
- Fault stays `#d94a4a` flat — not lacquer gradient. Red is breakage, not gloss.

We killed the oxblood `#8a0303` and the high-tech silver face. Everything red mapped to lime. If you see `#8a0303` or `#a30404`, it's a bug.

## Typography

- UI `Inter Variable 600` title `17px text-shadow 0 1px 0 rgba(0,0,0,0.65)`, body 13px 500, mono labels `Berkeley Mono 10px 1.5px #f8fafc` stamp like the deck silkscreen.
- Live LCD `Berkeley Mono 12px tabular` `color #7EFF3F` on `#030303` with phosphor `0 0 6px rgba(126,255,63,0.38)` + `0 0 14px rgba(126,255,63,0.12)` underglow + `0.02em` spacing. Unlit segments ghost `rgba(126,255,63,0.08)` dotted, not bright.
- Buttons `700 uppercase 0.06em` — short legends, not sentences. Dark text `#0a0a0c` on lime, off-black on garage black.

## Density & Feel — garage, not cockpit

- 4px base, gap 12px, but loosen the cockpit. Toretto's shop has space — one car, one bench. We dropped the Bloomberg density. Panels breathe 16px, wells 12px. Grids `wb 250px+1fr` etc keep the structure, but cards get smoked plastic + hairline scratch `repeating-linear-gradient(90deg, transparent 0 6px, rgba(255,255,255,0.02) 6px 7px)` very subtle, not slatted vents.
- Boldness in two places: lime tube + amber needle. Everything else shop-worn matte. No scanline CRT — this is FM deck phosphor, softer, warmer.
- Underglow: every selected well gets `box-shadow 0 0 10px rgba(126,255,63,0.14)` low to ground, like neon spilling from under the chassis onto concrete.
- Wood trim from the Toyota ref is gone. That was high-tech spec. Garage has no wood — just black vinyl + aluminum.

## Motion

- Ignition: LCD flicks on with 90ms glow ramp + tube fills `linear 1.1s` like coolant purging, needle sweeps 0→max→idle 400ms once. Press `translateY(1px) scale(0.99)` + inset `0 2px 6px rgba(0,0,0,0.45)` thud. `prefers-reduced-motion` cuts phosphor + sweep.

## Component contracts

- Gel button: lime gradient only on primary. Secondary stays `#1a1a20` matte with silver edge. Press is tactile 1px drop, not shine.
- Panel: `#0a0a0c` matte plate + top brushed hairline `rgba(200,205,208,0.12)` + left tick `3px linear-gradient(180deg,#9EFF6B,#5ACC2A)` on selected + underglow `0 0 10px rgba(126,255,63,0.10)` at bottom edge.
- Console/hex: sunken `#030303` phosphor LCD `color #7EFF3F glow` + faint ghost segments, no stark CRT lines. Border `1px rgba(0,0,0,0.6)` inset bevel.
- Coolant tube: clear acrylic look `background: #050507 / border 1px rgba(255,255,255,0.08)` with lime slug `88%` + `inset 0 1px 0 rgba(255,255,255,0.18)` highlight along top like liquid surface, plus `0 0 8px rgba(126,255,63,0.25)` outer glow.
- Sidebar/titlebar: DA shop signage — black plastic header `linear-gradient(180deg, rgba(255,255,255,0.06), transparent)` edge, brushed aluminum thin line, not a silver face. Active item gets lime tick + `rgba(126,255,63,0.10)` wash.

## Anti-slop

1. No `#8a0303` lacquer, no gold, no mirror chrome silver face. Only lime `#7EFF3F`.
2. No pills, no neon tags. Status = dot `6px #7EFF3F` + `10px mono` + underglow.
3. Lime only on live/selected/primary — not on static cards or chrome.
4. No wood trim now. No gloss cockpit. Matte shop.
5. One lime + one amber needle per view max. Grit over gloss.
