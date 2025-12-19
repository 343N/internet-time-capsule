<script lang="ts">
	import './layout.css';
	import favicon from '$lib/assets/favicon.svg';

	let { children } = $props();
</script>

<nav>
	<a href="/"><h1 class="site-title">internet time capsule</h1></a>
	<a href="/create">Create</a>
	<a href="/browse">Browse</a>
</nav>

<svelte:head><link rel="icon" href={favicon} /></svelte:head>
<main>

	{@render children()}
	
</main>