"use client"

import { useEffect, useRef } from "react"
import { motion } from "framer-motion"

interface Particle {
    x: number
    y: number
    size: number
    speedX: number
    speedY: number
    color: string
    alpha: number
    originalAlpha: number
}

interface ParticleBackgroundProps {
    mousePosition: { x: number; y: number }
}

export default function ParticleBackground({ mousePosition }: ParticleBackgroundProps) {
    const canvasRef = useRef<HTMLCanvasElement>(null)
    const particlesRef = useRef<Particle[]>([])
    const animationFrameRef = useRef<number>(0)
    const mouseRadius = 120 // Reduced radius of mouse influence
    const scrollRef = useRef({ x: 0, y: 0 }) // Add scroll position tracking

    // Colors for the particles
    const colors = [
        "#ef4444", // Red
        "#22d3ee", // Cyan
        "#a855f7", // Purple
        "#a3e635", // Lime
        "#818cf8", // Indigo
        "#fbbf24", // Amber
    ]

    useEffect(() => {
        // Update scroll position
        const handleScroll = () => {
            scrollRef.current = {
                x: window.scrollX,
                y: window.scrollY
            }
        }

        window.addEventListener('scroll', handleScroll)
        handleScroll() // Initialize scroll position

        return () => {
            window.removeEventListener('scroll', handleScroll)
        }
    }, [])

    useEffect(() => {
        const canvas = canvasRef.current
        if (!canvas) return
        // Initialize particles
        function initParticles() {
            if (!canvas) return;
            particlesRef.current = []
            const particleCount = Math.floor((canvas.width * canvas.height) / 12000) // Slightly higher density

            for (let i = 0; i < particleCount; i++) {
                const size = Math.random() * 2 + 1
                const alpha = Math.random() * 0.5 + 0.2
                particlesRef.current.push({
                    x: Math.random() * canvas.width,
                    y: Math.random() * canvas.height,
                    size,
                    speedX: Math.random() * 0.15 - 0.075, // Slower movement
                    speedY: Math.random() * 0.15 - 0.075, // Slower movement
                    color: colors[Math.floor(Math.random() * colors.length)],
                    alpha,
                    originalAlpha: alpha,
                })
            }
        }
        initParticles()

        // Set canvas to full window size
        const handleResize = () => {
            const body = document.getElementById('body')
            console.log(body?.offsetHeight, body?.offsetWidth)
            canvas.width = body?.offsetWidth || window.innerWidth
            canvas.height = body?.offsetHeight || window.innerHeight
            initParticles()
        }

        window.addEventListener("resize", handleResize)
        handleResize()

        return () => {
            window.removeEventListener("resize", handleResize)
        }
    }, [])

    useEffect(() => {
        const canvas = canvasRef.current
        if (!canvas) return

        const ctx = canvas.getContext("2d")
        if (!ctx) return


        // Animation loop
        function animate() {
            if (!canvas || !ctx) return;
            ctx.clearRect(0, 0, canvas.width, canvas.height)

            particlesRef.current.forEach((particle) => {
                // Calculate distance from mouse, accounting for scroll position
                const dx = (mousePosition.x + scrollRef.current.x) - particle.x
                const dy = (mousePosition.y + scrollRef.current.y) - particle.y
                const distance = Math.sqrt(dx * dx + dy * dy)

                // Particle behavior based on mouse proximity
                if (distance < mouseRadius) {
                    // Increase brightness and size near mouse
                    const intensity = 1 - distance / mouseRadius

                    // Push particles away from mouse (repulsor effect)
                    const angle = Math.atan2(dy, dx)
                    const repulsionForce = 1.5 * intensity
                    particle.x -= Math.cos(angle) * repulsionForce
                    particle.y -= Math.sin(angle) * repulsionForce

                    // Increase alpha (brightness) near mouse
                    particle.alpha = Math.min(1, particle.originalAlpha + intensity * 0.8)

                    // Draw connection lines between nearby particles
                    particlesRef.current.forEach((otherParticle) => {
                        const d = Math.sqrt(Math.pow(particle.x - otherParticle.x, 2) + Math.pow(particle.y - otherParticle.y, 2))

                        if (d < 50 && distance < mouseRadius) {
                            ctx.beginPath()
                            ctx.strokeStyle = `${particle.color}${Math.floor(intensity * 50).toString(16)}`
                            ctx.lineWidth = 0.3
                            ctx.moveTo(particle.x, particle.y)
                            ctx.lineTo(otherParticle.x, otherParticle.y)
                            ctx.stroke()
                        }
                    })
                } else {
                    // Reset alpha when away from mouse
                    particle.alpha = particle.originalAlpha
                }

                // Update particle position with inertia
                particle.x += particle.speedX
                particle.y += particle.speedY

                // Wrap around edges
                if (particle.x < 0) particle.x = canvas.width
                if (particle.x > canvas.width) particle.x = 0
                if (particle.y < 0) particle.y = canvas.height
                if (particle.y > canvas.height) particle.y = 0

                // Draw particle
                ctx.beginPath()
                ctx.arc(particle.x, particle.y, particle.size, 0, Math.PI * 2)
                ctx.fillStyle = `${particle.color}${Math.floor(particle.alpha * 255).toString(16)}`
                ctx.fill()

                // Add glow effect
                ctx.shadowBlur = 10
                ctx.shadowColor = particle.color
            })

            animationFrameRef.current = requestAnimationFrame(animate)
        }

        animate()

        return () => {
            cancelAnimationFrame(animationFrameRef.current)
        }
    }, [mousePosition])

    return (
        <motion.canvas
            ref={canvasRef}
            className="absolute inset-0 z-0"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 1 }}
        />
    )
}
