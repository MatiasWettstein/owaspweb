"use client"

import { useEffect, useState } from 'react'
import { ArrowUp } from 'lucide-react'

export default function ScrollToTop() {
    const [isVisible, setIsVisible] = useState(false)

    useEffect(() => {
        const toggleVisibility = () => {
            if (window.pageYOffset > 200) {
                setIsVisible(true)
            } else {
                setIsVisible(false)
            }
        }

        window.addEventListener('scroll', toggleVisibility)

        return () => {
            window.removeEventListener('scroll', toggleVisibility)
        }
    }, [])

    const scrollToTop = () => {
        window.scrollTo({
            top: 0,
            behavior: 'smooth'
        })
    }

    return (
        <button
            onClick={scrollToTop}
            aria-label="Scroll to top"
            className={`
        fixed bottom-5 right-5 
        bg-red-700/90 hover:bg-red-800 
        text-white 
        w-10 h-10 
        rounded-full 
        flex items-center justify-center 
        cursor-pointer 
        shadow-lg 
        z-50 
        transition-all duration-500 ease-in-out
        hover:-translate-y-1
        ${isVisible
                    ? 'opacity-100 visible'
                    : 'opacity-0 invisible pointer-events-none'
                }
      `}
        >
            <ArrowUp size={20} />
        </button>
    )
}