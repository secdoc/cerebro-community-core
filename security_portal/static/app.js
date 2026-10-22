const $ = id => document.getElementById(id);
function node(tag, text, parent) { const el = document.createElement(tag); el.textContent = String(text ?? '—'); parent.appendChild(el); return el; }
async function refresh() {
  try {
    const response = await fetch('/api/v1/overview', {cache: 'no-store'});
    if (!response.ok) throw new Error('API unavailable');
    const data = await response.json();
    $('title').textContent = data.portal.title;
    $('classification').textContent = data.portal.classification;
    $('status').textContent = `Updated ${data.overview.generated_at} · ${data.overview.state}`;
    $('overview').replaceChildren();
    node('p', `${data.overview.integration_count} sources · ${data.overview.nonhealthy_count} not healthy`, $('overview'));
    const list = $('integrations'); list.replaceChildren();
    for (const item of data.integrations) {
      const card = document.createElement('article');
      node('h3', `${item.name} · ${item.state}`, card);
      node('p', `Freshness: ${item.freshness} · category: ${item.category}`, card);
      const dl = document.createElement('dl');
      for (const [key, value] of Object.entries(item.summary || {})) {
        node('dt', key, dl); node('dd', value, dl);
      }
      card.appendChild(dl);
      if (item.deep_link) { const a = node('a', 'Open source console', card); a.href = item.deep_link; a.rel = 'noopener noreferrer'; a.target = '_blank'; }
      list.appendChild(card);
    }
    window.setTimeout(refresh, Math.max(10, data.portal.refresh_seconds) * 1000);
  } catch (_) { $('status').textContent = 'Portal data unavailable'; window.setTimeout(refresh, 30000); }
}
refresh();
