import './style.css';

const app = document.querySelector<HTMLDivElement>('#app');

if (!app) {
  throw new Error('App root not found.');
}

app.innerHTML = `
  <main class="shell">
    <section class="hero">
      <p class="eyebrow">crypto-lab</p>
      <h1>Paillier Gate</h1>
      <p class="lede">Additive homomorphic encryption in the browser.</p>
    </section>
  </main>
`;