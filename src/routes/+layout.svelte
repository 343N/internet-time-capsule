<script lang="ts">
	import './layout.css';
	import favicon from '$lib/assets/favicon.svg';

	let { children } = $props();
</script>

<nav>
	<a href="/">Home</a>
	<a href="/about">About</a>
</nav>

<svelte:head><link rel="icon" href={favicon} /></svelte:head>
{@render children()}
